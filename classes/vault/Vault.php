<?php

require_once(__DIR__ . '/VaultError.php');
require_once(__DIR__ . '/VaultStore.php');
require_once(__DIR__ . '/VaultCrypto.php');
require_once(__DIR__ . '/VaultConfig.php');
require_once(__DIR__ . '/VaultIdentity.php');
require_once(__DIR__ . '/VaultAuth.php');
require_once(__DIR__ . '/VaultAudit.php');
require_once(__DIR__ . '/VaultUsers.php');
require_once(__DIR__ . '/VaultServers.php');
require_once(__DIR__ . '/VaultCredentials.php');
require_once(__DIR__ . '/VaultFormat.php');
require_once(__DIR__ . '/VaultConnect.php');

/**
 * The login vault for this request: config, store, crypto, audit log, users
 * and the signed-in identity. lib.inc.php boots it on every page; the result
 * is the global $vault.
 */
class Vault {

	/** @var array normalised config, see VaultConfig::fromConf() */
	public $config;
	/** @var PDO */
	public $db;
	/** @var VaultCrypto */
	public $crypto;
	/** @var VaultAudit */
	public $audit;
	/** @var VaultUsers */
	public $users;
	/** @var VaultServers */
	public $servers;
	/** @var VaultCredentials */
	public $creds;
	/** @var VaultIdentity|null */
	public $identity = null;

	/**
	 * Opens everything and works out who is asking. In sso mode a request
	 * that isn't from a trusted proxy, or has no usable user header, gets a
	 * 403 here and nothing else of the app runs.
	 * @throws VaultError on a configuration or storage problem
	 */
	public static function boot(array &$conf, string $script): Vault {
		$vault = new Vault();
		$vault->config = VaultConfig::fromConf($conf);
		$vault->crypto = VaultCrypto::fromConfig($vault->config);
		$vault->db = VaultStore::open($vault->config['db_path']);
		$vault->audit = new VaultAudit($vault->db);
		$vault->users = new VaultUsers($vault->db, $vault->audit);
		$vault->servers = new VaultServers($vault->db, $vault->audit);
		$vault->creds = new VaultCredentials($vault->db, $vault->crypto, $vault->audit);

		// Mirror the env servers into the table and add the UI ones, before
		// anything looks a server up.
		try {
			$envServers = isset($conf['servers']) && is_array($conf['servers']) ? $conf['servers'] : array();
			$vault->servers->syncEnv($envServers, VaultStore::now());
			$conf['servers'] = $vault->servers->confServers($envServers, $vault->config['ui_defaults'],
				!empty($vault->config['servers_allow_ui']));
		} catch (PDOException $e) {
			throw new VaultError('The vault database failed: ' . $e->getMessage(), 0, $e);
		}

		try {
			if ($vault->config['auth_mode'] === 'sso') {
				$why = null;
				$identity = VaultAuth::ssoIdentity($_SERVER, $vault->config, $why);
				if ($identity === null) {
					if ($why === 'untrusted') {
						error_log('phpPgAdmin: refused a request from ' . ($_SERVER['REMOTE_ADDR'] ?? '?')
							. ', which is not in AUTH_TRUSTED_PROXIES');
						self::fail(403, self::text('strvaultuntrusted', 'This request did not come through the sign-in proxy.'));
					}
					self::fail(403, self::text('strvaultnouser', 'The sign-in proxy did not say who you are.'));
				}
				if ($vault->users->isDisabled($identity->username)) {
					self::fail(403, self::text('strvaultdisabled', 'Your account is disabled.'));
				}
				$vault->users->seen($identity->username);
				$vault->identity = $identity;
				// Idle first: a session it clears is simply bound again.
				self::applyIdleTimeout($vault->config['idle_minutes']);
				self::bindSession($identity->username);
			} else {
				// Local mode: the identity comes from a sign-in on signin.php.
				// After an idle timeout there is none.
				self::applyIdleTimeout($vault->config['idle_minutes']);
				$vault->identity = $vault->localIdentity();
				if ($vault->identity === null && $script !== 'signin.php') {
					self::toSignin($script);
				}
			}
		} catch (PDOException $e) {
			throw new VaultError('The vault database failed: ' . $e->getMessage(), 0, $e);
		}

		$GLOBALS['vault'] = $vault;
		return $vault;
	}

	/**
	 * After idle_minutes without a request the session starts empty: the
	 * local sign-in, database logins and all. 0 turns this off.
	 */
	private static function applyIdleTimeout(int $minutes): void {
		if (session_status() !== PHP_SESSION_ACTIVE) {
			return;
		}
		$seen = isset($_SESSION['ppa_seen']) ? $_SESSION['ppa_seen'] : null;
		if ($minutes > 0 && is_int($seen) && time() - $seen > $minutes * 60) {
			$_SESSION = array();
			session_regenerate_id(true);
		}
		$_SESSION['ppa_seen'] = time();
	}

	/**
	 * The local account signed in to this session, or null. An account that
	 * was removed or disabled since ends the session.
	 */
	private function localIdentity(): ?VaultIdentity {
		$username = isset($_SESSION['ppa_auth_user']) ? $_SESSION['ppa_auth_user'] : null;
		if (!is_string($username) || $username === '') {
			return null;
		}
		$row = $this->users->get($username);
		if ($row === null || (int)$row['disabled'] !== 0) {
			$_SESSION = array();
			return null;
		}
		$this->users->seen($username);
		return new VaultIdentity($username, $this->users->groupsOf($username), $this->config['admin_group'], 'local');
	}

	/**
	 * Sends someone who isn't signed in (local mode) to signin.php, which
	 * brings them back to this page afterwards. The app shell's requests
	 * get a 401 that tells it where to go instead.
	 */
	private static function toSignin(string $script): void {
		if (self::isPartial()) {
			self::sendSignin('signin.php');
		}
		$query = isset($_SERVER['QUERY_STRING']) ? (string)$_SERVER['QUERY_STRING'] : '';
		$next = self::safeNext($script . ($query !== '' ? '?' . $query : ''));
		self::redirect('signin.php' . ($next !== null ? '?next=' . rawurlencode($next) : ''));
	}

	/**
	 * Handles the sign-in form (local mode) and Sign out (both modes). Runs
	 * after the CSRF check and while the session is still open, so the
	 * session id can be changed.
	 */
	public function handleAuthPost(string $script): void {
		if (($_SERVER['REQUEST_METHOD'] ?? 'GET') !== 'POST') {
			return;
		}
		try {
			if ($script === 'signout.php') {
				$this->signOut();
			}
			if ($script === 'signin.php' && $this->config['auth_mode'] === 'local') {
				$this->signIn();
			}
		} catch (PDOException $e) {
			self::unavailable($e);
		}
	}

	private function signIn(): void {
		$username = isset($_POST['username']) && is_string($_POST['username']) ? trim($_POST['username']) : '';
		$password = isset($_POST['password']) && is_string($_POST['password']) ? $_POST['password'] : '';
		$next = self::safeNext(isset($_POST['next']) && is_string($_POST['next']) ? $_POST['next'] : '');

		$result = $this->users->verify($username, $password, VaultStore::now());
		if ($result === 'ok') {
			// A new session for the signed-in person: a new id (no fixation),
			// a new CSRF token, and nothing left from whoever used it before.
			$_SESSION = array();
			session_regenerate_id(true);
			$_SESSION['ppa_auth_user'] = $username;
			$_SESSION['ppa_seen'] = time();
			self::redirect($next !== null ? $next : 'intro.php');
		}

		// A password typed into Username must not end up in the audit log:
		// only a name that is an account is recorded.
		$actor = $this->users->get($username) !== null ? mb_substr($username, 0, 128, 'UTF-8') : '(unknown)';
		$this->audit->log($actor, VaultAudit::SIGNIN_FAILED, array('detail' => array('result' => $result)));
		$_SESSION['ppa_flash'] = $result === 'locked'
			? self::text('strvaultsigninlocked', 'Too many failed sign-ins. Try again in 5 minutes.')
			: self::text('strvaultsigninbad', 'Wrong username or password.');
		self::redirect('signin.php' . ($next !== null ? '?next=' . rawurlencode($next) : ''));
	}

	private function signOut(): void {
		if ($this->config['auth_mode'] === 'local') {
			$target = 'signin.php';
		} else {
			$target = $this->config['signout_url'] !== '' ? $this->config['signout_url'] : 'intro.php';
		}
		$_SESSION = array();
		if (session_status() === PHP_SESSION_ACTIVE) {
			$cookie = session_get_cookie_params();
			if (!headers_sent() && ini_get('session.use_cookies')) {
				setcookie(session_name(), '', array(
					'expires' => time() - 3600,
					'path' => $cookie['path'],
					'domain' => $cookie['domain'],
					'secure' => $cookie['secure'],
					'httponly' => $cookie['httponly'],
					'samesite' => isset($cookie['samesite']) ? $cookie['samesite'] : '',
				));
			}
			session_destroy();
		}
		if (self::isPartial()) {
			self::sendSignin($target);
		}
		self::redirect($target);
	}

	/**
	 * $next if it is one of the app's own pages ("name.php" with an
	 * optional query), else null. Never another site, and never the
	 * sign-in or sign-out pages themselves.
	 */
	public static function safeNext(string $next): ?string {
		// Printable ASCII only: it ends up in a Location header.
		if (!preg_match('/^[a-z_]+\.php(\?[\x21-\x7E]*)?$/D', $next)) {
			return null;
		}
		if (preg_match('/^(signin|signout|logout)\.php/', $next)) {
			return null;
		}
		return $next;
	}

	/** True for a request from the app shell (js/app.js), see Misc::isPartialRequest(). */
	private static function isPartial(): bool {
		return ($_SERVER['HTTP_X_PPA_PARTIAL'] ?? '') === '1';
	}

	/** 401 for the app shell, with where to go in X-PPA-Signin. */
	private static function sendSignin(string $target): void {
		http_response_code(401);
		header('X-PPA-Signin: ' . $target);
		header('Content-Type: text/plain; charset=utf-8');
		header('Cache-Control: no-store');
		echo self::text('strvaultsigninagain', 'Sign in again.'), "\n";
		exit;
	}

	/** 303 to a page of the app (or the sso sign-out URL). */
	public static function redirect(string $url): void {
		header('Location: ' . $url, true, 303);
		header('Cache-Control: no-store');
		exit;
	}

	/**
	 * Ties the PHP session to the person the proxy vouches for. When someone
	 * else turns up with the same session cookie (a different person signed
	 * in at the proxy in the same browser), the session starts empty, so
	 * they never inherit the previous person's database logins.
	 */
	private static function bindSession(string $username): void {
		if (session_status() !== PHP_SESSION_ACTIVE) {
			return;
		}
		if (isset($_SESSION['ppa_sso_user']) && $_SESSION['ppa_sso_user'] !== $username) {
			$_SESSION = array();
			session_regenerate_id(true);
		}
		$_SESSION['ppa_sso_user'] = $username;
	}

	/**
	 * Stops the request with a bare page that holds only $message: no app
	 * shell and no theme, since those may not be set up yet.
	 */
	public static function fail(int $code, string $message): void {
		if (!headers_sent()) {
			http_response_code($code);
			header('Content-Type: text/html; charset=utf-8');
			header('Cache-Control: no-store');
		}
		echo "<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n",
			"<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n",
			"<title>phpPgAdmin</title>\n</head>\n<body>\n<h1>phpPgAdmin</h1>\n<p>",
			htmlspecialchars($message, ENT_QUOTES, 'UTF-8'), "</p>\n</body>\n</html>\n";
		exit;
	}

	/**
	 * Stops the request with HTTP 500 and a generic "unavailable" page. The
	 * detail (a path, the PDO message) goes to the error log only: the page
	 * may be seen by someone who isn't signed in.
	 */
	public static function unavailable(Throwable $e): void {
		error_log('phpPgAdmin: the login vault is unavailable: ' . get_class($e) . ': ' . $e->getMessage());
		self::fail(500, self::text('strvaultunavailable', 'The login vault is unavailable. The server log has the details.'));
	}

	/**
	 * The exception handler lib.inc.php installs: a vault storage error
	 * nobody caught gets the generic page instead of a blank 500. Anything
	 * else is reported the way PHP reports an uncaught exception (a
	 * rethrow from here would come back to this handler on PHP 8.5).
	 */
	public static function uncaught(Throwable $e): void {
		if ($e instanceof PDOException || $e instanceof VaultError) {
			self::unavailable($e);
		}
		$text = 'Uncaught ' . $e . "\n  thrown in " . $e->getFile() . ' on line ' . $e->getLine();
		error_log('PHP Fatal error:  ' . $text);
		if (!headers_sent()) {
			http_response_code(500);
		}
		if (filter_var(ini_get('display_errors'), FILTER_VALIDATE_BOOLEAN)) {
			echo "\nFatal error: ", htmlspecialchars($text, ENT_QUOTES, 'UTF-8'), "\n";
		}
		exit(255);
	}

	/** "Too many failed logins. Try again in N minutes." for $seconds left (1 minute, 2 minutes...). */
	public static function loginLockMessage(int $seconds): string {
		$minutes = max(1, (int)ceil($seconds / 60));
		if ($minutes === 1) {
			return self::text('strvaultloginlockedone', 'Too many failed logins. Try again in 1 minute.');
		}
		return sprintf(self::text('strvaultloginlocked', 'Too many failed logins. Try again in %d minutes.'), $minutes);
	}

	/**
	 * application_name for Postgres connections: "phppgadmin:<username>",
	 * printable ASCII only and at most 63 bytes (what Postgres keeps).
	 */
	public static function appName(string $username): string {
		$name = $username === '' ? 'phppgadmin' : 'phppgadmin:' . $username;
		return substr(preg_replace('/[^\x20-\x7E]/', '?', $name), 0, 63);
	}

	/** Stops the request unless the signed-in person is an admin. */
	public function requireAdmin(): void {
		if ($this->identity === null || !$this->identity->isAdmin) {
			self::fail(403, self::text('strvaultadminonly', 'Only admins can open this page.'));
		}
	}

	private static function text(string $key, string $fallback): string {
		global $lang;
		return isset($lang[$key]) ? $lang[$key] : $fallback;
	}
}

/**
 * Called by the error handler (libraries/errorhandler.inc.php) when the
 * connection of a session login fails, before that login is dropped. Writes
 * the login_failed audit row the rate limit counts, and for a saved login
 * with a wrong password marks it failed and sets the global
 * $loginVaultFailed, so login.php can say the password needs updating.
 * Every failure is audited; the rate limit counts only wrong passwords
 * (VaultAudit::loginLockSeconds()).
 *
 * @param array $info the session login (see Misc::getServerInfo())
 * @param string $detail the server's message (never holds the password)
 */
function ppa_vault_login_failed(array $info, string $detail): void {
	global $vault;
	if (!isset($vault) || !($vault instanceof Vault) || $vault->identity === null || !isset($info['username'])) {
		return;
	}
	$reason = function_exists('loginErrorReasonKey') ? loginErrorReasonKey($detail) : '';
	$credential = isset($info['vault_credential']) ? (string)$info['vault_credential'] : null;
	try {
		$vault->audit->log($vault->identity->username, VaultAudit::LOGIN_FAILED, array(
			'credential_id' => $credential,
			'server_id' => isset($info['key']) ? (string)$info['key'] : null,
			'database' => (string)($info['defaultdb'] ?? 'postgres'),
			'detail' => array('pg_username' => (string)$info['username'], 'reason' => $reason),
		));
		if ($credential !== null && $reason === 'strloginbadpassword') {
			$vault->creds->markFailed($credential);
			$GLOBALS['loginVaultFailed'] = array(
				'id' => $credential,
				'kind' => (string)($info['vault_kind'] ?? ''),
				'label' => (string)($info['vault_label'] ?? ''),
			);
		}
	} catch (PDOException $e) {
		error_log('phpPgAdmin: the vault database failed: ' . $e->getMessage());
	}
}

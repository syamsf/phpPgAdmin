<?php

require_once(__DIR__ . '/VaultError.php');
require_once(__DIR__ . '/VaultStore.php');
require_once(__DIR__ . '/VaultAudit.php');

/**
 * App users. In sso mode a row only records that someone has been here (for
 * the audit log and "last seen"); their groups always come from the header.
 */
class VaultUsers {

	/** last_seen_at is only rewritten when it is older than this. */
	const SEEN_INTERVAL = 300;

	/** Failed sign-ins in a row that lock a local account, and for how long. */
	const MAX_FAILED = 5;
	const LOCK_SECONDS = 300;

	const MIN_PASSWORD = 12;

	/**
	 * Checked when the username is unknown, so that a wrong name takes as
	 * long as a wrong password. Its password is not used anywhere.
	 */
	const DUMMY_HASH = '$argon2id$v=19$m=65536,t=4,p=1$T2YyRjNiSWNIZG9nTy9kUA$LMZAX0H9WP/OjFnPzm3nLHHgpoty36ppdyoVlvACp78';

	private $db;
	private $audit;

	public function __construct(PDO $db, VaultAudit $audit) {
		$this->db = $db;
		$this->audit = $audit;
	}

	/** Records a visit: adds the row on the first one. */
	public function seen(string $username): void {
		$now = VaultStore::now();
		$stmt = $this->db->prepare('SELECT last_seen_at FROM users WHERE username = :u');
		$stmt->execute(array(':u' => $username));
		$row = $stmt->fetch();
		if ($row === false) {
			$this->db->prepare('INSERT OR IGNORE INTO users (username, last_seen_at, created_at) VALUES (:u, :now, :now)')
				->execute(array(':u' => $username, ':now' => $now));
			return;
		}
		$stale = gmdate('Y-m-d\TH:i:s\Z', time() - self::SEEN_INTERVAL);
		if ($row['last_seen_at'] === null || $row['last_seen_at'] < $stale) {
			$this->db->prepare('UPDATE users SET last_seen_at = :now WHERE username = :u')
				->execute(array(':u' => $username, ':now' => $now));
		}
	}

	public function isDisabled(string $username): bool {
		$stmt = $this->db->prepare('SELECT disabled FROM users WHERE username = :u');
		$stmt->execute(array(':u' => $username));
		return (int)$stmt->fetchColumn() !== 0;
	}

	/** The users row, or null. */
	public function get(string $username): ?array {
		$stmt = $this->db->prepare('SELECT * FROM users WHERE username = :u');
		$stmt->execute(array(':u' => $username));
		$row = $stmt->fetch();
		return $row === false ? null : $row;
	}

	/** The user's groups (local mode), sorted. */
	public function groupsOf(string $username): array {
		$stmt = $this->db->prepare('SELECT group_name FROM user_groups WHERE username = :u ORDER BY group_name');
		$stmt->execute(array(':u' => $username));
		$groups = $stmt->fetchAll(PDO::FETCH_COLUMN);
		sort($groups, SORT_STRING);
		return $groups;
	}

	/**
	 * Adds a local account.
	 * @throws VaultError (message is a $lang key) on a bad username, display
	 *   name, password or group, or when the username is taken
	 */
	public function add(string $username, string $displayName, string $password, array $groups, string $actor): void {
		if (!self::validUsername($username)) {
			throw new VaultError('strvaultbadusername');
		}
		$displayName = trim($displayName);
		if (strlen($displayName) > 128 || preg_match('/[\x00-\x1F\x7F]/', $displayName)) {
			throw new VaultError('strvaultbaddisplayname');
		}
		self::checkPassword($password);
		$groups = self::cleanGroups($groups);
		// Hashed before the write lock is taken: Argon2id takes a while.
		$hash = password_hash($password, PASSWORD_ARGON2ID);

		VaultStore::transaction($this->db, function () use ($username, $displayName, $hash, $groups, $actor) {
			if ($this->get($username) !== null) {
				throw new VaultError('strvaultuserexists');
			}
			$this->db->prepare('INSERT INTO users (username, display_name, password_hash, created_at) VALUES (:u, :d, :h, :now)')
				->execute(array(
					':u' => $username,
					':d' => $displayName,
					':h' => $hash,
					':now' => VaultStore::now(),
				));
			$stmt = $this->db->prepare('INSERT INTO user_groups (username, group_name) VALUES (:u, :g)');
			foreach ($groups as $group) {
				$stmt->execute(array(':u' => $username, ':g' => $group));
			}
			$this->audit->log($actor, VaultAudit::USER_ADDED, array('detail' => array('user' => $username, 'groups' => $groups)));
		});
	}

	/**
	 * Every local account with its groups, sorted by username.
	 * @return array rows of username, display_name, groups, disabled (bool), last_seen_at
	 */
	public function all(): array {
		$groups = array();
		foreach ($this->db->query('SELECT username, group_name FROM user_groups ORDER BY group_name') as $row) {
			$groups[$row['username']][] = $row['group_name'];
		}
		$out = array();
		foreach ($this->db->query('SELECT username, display_name, disabled, last_seen_at FROM users ORDER BY username') as $row) {
			$out[] = array(
				'username' => $row['username'],
				'display_name' => $row['display_name'],
				'groups' => isset($groups[$row['username']]) ? $groups[$row['username']] : array(),
				'disabled' => (int)$row['disabled'] !== 0,
				'last_seen_at' => $row['last_seen_at'],
			);
		}
		return $out;
	}

	/**
	 * Disables or enables an account. Disabling also removes the shares made
	 * directly to the person (offboarding); group shares are untouched.
	 * @throws VaultError('strvaultusernotfound')
	 */
	public function setDisabled(string $username, bool $disabled, string $actor): void {
		VaultStore::transaction($this->db, function () use ($username, $disabled, $actor) {
			if ($this->get($username) === null) {
				throw new VaultError('strvaultusernotfound');
			}
			$this->db->prepare('UPDATE users SET disabled = :d WHERE username = :u')
				->execute(array(':d' => $disabled ? 1 : 0, ':u' => $username));
			if ($disabled) {
				$this->db->prepare("DELETE FROM credential_shares WHERE principal_type = 'user' AND principal = :u")
					->execute(array(':u' => $username));
			}
			$this->audit->log($actor, $disabled ? VaultAudit::USER_DISABLED : VaultAudit::USER_ENABLED,
				array('detail' => array('user' => $username)));
		});
	}

	/**
	 * Sets a new password and clears the sign-in lockout.
	 * @throws VaultError on a short password or an unknown user
	 */
	public function resetPassword(string $username, string $password, string $actor): void {
		self::checkPassword($password);
		$hash = password_hash($password, PASSWORD_ARGON2ID);
		VaultStore::transaction($this->db, function () use ($username, $hash, $actor) {
			if ($this->get($username) === null) {
				throw new VaultError('strvaultusernotfound');
			}
			$this->db->prepare('UPDATE users SET password_hash = :h, failed_attempts = 0, locked_until = NULL WHERE username = :u')
				->execute(array(':h' => $hash, ':u' => $username));
			$this->audit->log($actor, VaultAudit::PASSWORD_RESET, array('detail' => array('user' => $username)));
		});
	}

	/**
	 * Replaces the user's groups.
	 * @throws VaultError on a bad group name or an unknown user
	 */
	public function setGroups(string $username, array $groups, string $actor): void {
		$groups = self::cleanGroups($groups);
		VaultStore::transaction($this->db, function () use ($username, $groups, $actor) {
			if ($this->get($username) === null) {
				throw new VaultError('strvaultusernotfound');
			}
			$before = $this->groupsOf($username);
			$this->db->prepare('DELETE FROM user_groups WHERE username = :u')->execute(array(':u' => $username));
			$stmt = $this->db->prepare('INSERT INTO user_groups (username, group_name) VALUES (:u, :g)');
			foreach ($groups as $group) {
				$stmt->execute(array(':u' => $username, ':g' => $group));
			}
			$this->audit->log($actor, VaultAudit::GROUPS_CHANGED,
				array('detail' => array('user' => $username, 'before' => $before, 'after' => $groups)));
		});
	}

	/**
	 * Checks a local sign-in at time $now (VaultStore::now() format).
	 * @return string 'ok', 'bad' (unknown user or wrong password), 'locked'
	 *   (too many failures; the password is not checked) or 'disabled'
	 */
	public function verify(string $username, string $password, string $now): string {
		$row = $this->get($username);
		if ($row !== null && $row['locked_until'] !== null && $row['locked_until'] > $now) {
			return 'locked';
		}
		$hash = ($row !== null && is_string($row['password_hash']) && $row['password_hash'] !== '')
			? $row['password_hash'] : null;
		// Always one Argon2id check, so the answer takes as long for every name.
		$ok = password_verify($password, $hash !== null ? $hash : self::DUMMY_HASH) && $hash !== null;
		if ($row === null) {
			return 'bad';
		}
		if ((int)$row['disabled'] !== 0) {
			return 'disabled';
		}
		if ($ok) {
			if ((int)$row['failed_attempts'] !== 0 || $row['locked_until'] !== null) {
				$this->db->prepare('UPDATE users SET failed_attempts = 0, locked_until = NULL WHERE username = :u')
					->execute(array(':u' => $username));
			}
			return 'ok';
		}

		VaultStore::transaction($this->db, function () use ($username, $now) {
			$this->db->prepare('UPDATE users SET failed_attempts = failed_attempts + 1 WHERE username = :u')
				->execute(array(':u' => $username));
			$stmt = $this->db->prepare('SELECT failed_attempts FROM users WHERE username = :u');
			$stmt->execute(array(':u' => $username));
			if ((int)$stmt->fetchColumn() >= self::MAX_FAILED) {
				$this->db->prepare('UPDATE users SET failed_attempts = 0, locked_until = :until WHERE username = :u')
					->execute(array(':u' => $username, ':until' => gmdate('Y-m-d\TH:i:s\Z', strtotime($now) + self::LOCK_SECONDS)));
			}
		});
		return 'bad';
	}

	public static function validUsername(string $username): bool {
		return (bool)preg_match('/^[A-Za-z0-9._@-]{1,64}$/D', $username);
	}

	/** @throws VaultError('strvaultshortpassword') */
	public static function checkPassword(string $password): void {
		$length = function_exists('mb_strlen') ? mb_strlen($password, 'UTF-8') : strlen($password);
		if ($length < self::MIN_PASSWORD) {
			throw new VaultError('strvaultshortpassword');
		}
	}

	/**
	 * Trimmed, without empty items or doubles, sorted.
	 * @throws VaultError('strvaultbadgroup') on a group name that is too
	 *   long or holds a control character or a comma
	 */
	public static function cleanGroups(array $groups): array {
		$clean = array();
		foreach ($groups as $group) {
			$group = trim((string)$group);
			if ($group === '') {
				continue;
			}
			if (strlen($group) > 64 || preg_match('/[\x00-\x1F\x7F,]/', $group)) {
				throw new VaultError('strvaultbadgroup');
			}
			$clean[$group] = true;
		}
		$clean = array_keys($clean);
		sort($clean, SORT_STRING);
		return array_map('strval', $clean);
	}
}

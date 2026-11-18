<?php

	/**
	 * My saved logins: the signed-in person's own saved Postgres logins
	 * (rename, update password, delete) and the shared ones they can use.
	 * Works on the person's personal logins only; shared logins are managed
	 * by admins elsewhere.
	 */

	// Not tied to a server
	$_no_db_connection = true;
	include_once('./libraries/lib.inc.php');

	$vault_who = (isset($vault) && $vault instanceof Vault) ? $vault->identity : null;
	if ($vault_who === null) {
		echo htmlspecialchars($lang['strvaultnouser']);
		exit;
	}

	$action = (isset($_REQUEST['action']) && is_scalar($_REQUEST['action'])) ? (string) $_REQUEST['action'] : '';
	$vault_id = (isset($_REQUEST['id']) && is_scalar($_REQUEST['id'])) ? (string) $_REQUEST['id'] : '';

	/** A message above the page content: $error picks the alert style. */
	function vaultMsg($text, $error = false) {
		if ($text === '') return;
		echo "<p class=\"message", ($error ? ' error' : ''), "\" role=\"", ($error ? 'alert' : 'status'), "\">",
			htmlspecialchars($text), "</p>\n";
	}

	/** The text of a VaultError (its message is a $lang key). */
	function vaultErrorText(VaultError $e) {
		global $lang;
		return isset($lang[$e->getMessage()]) ? $lang[$e->getMessage()] : $e->getMessage();
	}

	/** One of my personal logins, or null (unknown, someone else's, shared). */
	function vaultMyLogin($id) {
		global $vault, $vault_who;
		if ($id === '') return null;
		$row = $vault->creds->get($vault_who, $id);
		return ($row !== null && $row['kind'] === 'personal') ? $row : null;
	}

	function vaultTag($access) {
		global $lang;
		return '<span class="vault-tag ' . ($access === 'read-only' ? 'vault-tag-ro' : 'vault-tag-rw') . '">'
			. htmlspecialchars($access === 'read-only' ? $lang['strvaultreadonly'] : $lang['strvaultreadwrite']) . '</span>';
	}

	function vaultServerName($key) {
		global $vault;
		$server = $vault->servers->get($key);
		return $server !== null && $server['name'] !== '' ? $server['name'] : $key;
	}

	function vaultCount($n) {
		global $lang;
		return $n === 1 ? $lang['strvaultonelogin'] : sprintf($lang['strvaultnlogins'], $n);
	}

	/** Rows of one table grouped by server, with a header row per server. */
	function vaultGroupRow($key, $n, $cols) {
		return "<tr><th scope=\"colgroup\" colspan=\"{$cols}\" class=\"vault-group\">" . htmlspecialchars(vaultServerName($key))
			. " <span>· " . htmlspecialchars(vaultCount($n)) . "</span></th></tr>\n";
	}

	function doDefault($msg = '', $error = false) {
		global $misc, $lang, $vault, $vault_who;

		$misc->printTrail('root');
		$misc->printTabs('root', 'vault');
		vaultMsg($msg, $error);

		$now = time();
		$mine = array();
		$shared = array();
		try {
			$mine = $vault->creds->mine($vault_who);
			$shared = $vault->creds->sharedWithMe($vault_who, VaultStore::now());
		} catch (PDOException $e) {
			error_log('phpPgAdmin: the vault database failed: ' . $e->getMessage());
			vaultMsg($lang['strvaultstorefailed'], true);
		}

		echo "<div class=\"vault-page\">\n";
		echo "<h2>", htmlspecialchars($lang['strvaultmylogins']), "</h2>\n";
		echo "<p class=\"vault-intro\">", htmlspecialchars($lang['strvaultmyintro']), "</p>\n";

		// Mine
		echo "<section aria-labelledby=\"vault-mine-h\">\n";
		echo "<h3 id=\"vault-mine-h\">", htmlspecialchars(sprintf('%s (%d)', $lang['strvaultmine'], count($mine))), "</h3>\n";
		if ($mine) {
			$counts = array();
			foreach ($mine as $row) {
				$counts[$row['server_id']] = ($counts[$row['server_id']] ?? 0) + 1;
			}
			echo "<div class=\"vault-table-wrap\">\n<table class=\"vault-table\">\n<thead><tr>";
			foreach (array('strvaultlabel', 'strdatabase', 'strvaultpguser', 'strvaultaccess', 'strvaultlastused', 'strvaultstatus', 'stractions') as $key) {
				echo "<th scope=\"col\">", htmlspecialchars($lang[$key]), "</th>";
			}
			echo "</tr></thead>\n<tbody>\n";
			$current = null;
			foreach ($mine as $row) {
				if ($row['server_id'] !== $current) {
					$current = $row['server_id'];
					echo vaultGroupRow($current, $counts[$current], 7);
				}
				$failed = $row['last_status'] === 'auth_failed';
				$id = rawurlencode($row['id']);
				echo "<tr", $failed ? ' class="vault-row-failed"' : '', ">\n";
				echo "<td class=\"vault-label\">", htmlspecialchars($row['label']), "</td>\n";
				echo "<td>", htmlspecialchars($row['database']), "</td>\n";
				echo "<td class=\"vault-mono\">", htmlspecialchars($row['pg_username']), "</td>\n";
				echo "<td>", vaultTag($row['access_label']), "</td>\n";
				echo "<td>", htmlspecialchars(VaultFormat::ago($row['last_used_at'], $now)), "</td>\n";
				echo "<td>", $failed
					? '<span class="vault-status vault-status-failed">' . htmlspecialchars($lang['strvaultpasswordfailed']) . '</span>'
					: '<span class="vault-status vault-status-ok">' . htmlspecialchars($lang['strvaultok']) . '</span>', "</td>\n";
				echo "<td class=\"vault-actions\">",
					"<a href=\"vault.php?action=rename&amp;id={$id}\" data-ppa-dialog=\"modal\">", htmlspecialchars($lang['strvaultrename']), "</a> · ",
					"<a href=\"vault.php?action=password&amp;id={$id}\" data-ppa-dialog=\"modal\"", $failed ? ' class="vault-fix"' : '', ">", htmlspecialchars($lang['strvaultupdatepassword']), "</a> · ",
					"<a href=\"vault.php?action=delete&amp;id={$id}\" data-ppa-dialog=\"modal\" class=\"vault-delete-link\">", htmlspecialchars($lang['strdelete']), "</a>",
					"</td>\n</tr>\n";
			}
			echo "</tbody>\n</table>\n</div>\n";
		}
		echo "<p class=\"vault-note\">", htmlspecialchars($lang['strvaultaddhint']), "</p>\n";
		echo "</section>\n";

		// Shared with me
		echo "<section aria-labelledby=\"vault-shared-h\">\n";
		echo "<h3 id=\"vault-shared-h\">", htmlspecialchars(sprintf('%s (%d)', $lang['strvaultsharedwithme'], count($shared))), "</h3>\n";
		if ($shared) {
			$counts = array();
			foreach ($shared as $row) {
				$counts[$row['server_id']] = ($counts[$row['server_id']] ?? 0) + 1;
			}
			echo "<div class=\"vault-table-wrap\">\n<table class=\"vault-table\">\n<thead><tr>";
			foreach (array('strvaultlabel', 'strdatabase', 'strvaultpguser', 'strvaultaccess', 'strvaultthrough', 'strvaultexpires') as $key) {
				echo "<th scope=\"col\">", htmlspecialchars($lang[$key]), "</th>";
			}
			echo "</tr></thead>\n<tbody>\n";
			$current = null;
			foreach ($shared as $row) {
				if ($row['server_id'] !== $current) {
					$current = $row['server_id'];
					echo vaultGroupRow($current, $counts[$current], 6);
				}
				echo "<tr>\n";
				echo "<td class=\"vault-label\">", htmlspecialchars($row['label']), "</td>\n";
				echo "<td>", htmlspecialchars($row['database']), "</td>\n";
				echo "<td class=\"vault-mono\">", htmlspecialchars($row['pg_username']), "</td>\n";
				echo "<td>", vaultTag($row['access_label']), "</td>\n";
				if ($row['via'] === 'you') {
					echo "<td>", htmlspecialchars($lang['strvaultthroughyou']), "</td>\n";
				} else {
					echo "<td>", htmlspecialchars($lang['strvaultthroughgroup']), " <strong>",
						htmlspecialchars(substr((string) $row['via'], strlen('group:'))), "</strong></td>\n";
				}
				echo $row['expires_at'] === null
					? "<td>" . htmlspecialchars($lang['strvaultmetanoexpiry']) . "</td>\n"
					: "<td class=\"vault-expires\">" . htmlspecialchars(VaultFormat::date($row['expires_at'])) . "</td>\n";
				echo "</tr>\n";
			}
			echo "</tbody>\n</table>\n</div>\n";
		}
		echo "<p class=\"vault-lock-note\"><svg width=\"14\" height=\"14\" viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"2\" stroke-linecap=\"round\" stroke-linejoin=\"round\" aria-hidden=\"true\" focusable=\"false\"><rect x=\"5\" y=\"11\" width=\"14\" height=\"10\" rx=\"2\"></rect><path d=\"M8 11V7a4 4 0 0 1 8 0v4\"></path></svg><span>",
			htmlspecialchars($lang['strvaultsharednote']), "</span></p>\n";
		echo "</section>\n";
		echo "</div>\n";
	}

	/** The head of a dialog page; null (after the list with a message) when the login isn't mine. */
	function vaultFormPage($id, $title) {
		global $misc, $lang;

		$row = vaultMyLogin($id);
		if ($row === null) {
			doDefault($lang['strvaultnotfound'], true);
			return null;
		}
		$misc->printTrail('root');
		$misc->printTitle($title);
		return $row;
	}

	function vaultButtons($doLabel) {
		global $lang;
		echo "<p><input type=\"submit\" class=\"vault-primary\" value=\"", htmlspecialchars($doLabel), "\" /> ",
			"<input type=\"submit\" name=\"cancel\" value=\"", htmlspecialchars($lang['strcancel']), "\" formnovalidate=\"formnovalidate\" /></p>\n";
	}

	function doRename($label = null, $access = null) {
		global $misc, $lang, $vault_id;

		$row = vaultFormPage($vault_id, $lang['strvaultrename']);
		if ($row === null) return;
		$label = $label === null ? $row['label'] : $label;
		$access = $access === null ? $row['access_label'] : $access;

		echo "<form action=\"vault.php\" method=\"post\" class=\"vault-form\">\n";
		echo "<p class=\"vault-where\">", htmlspecialchars(vaultServerName($row['server_id'])), " · ",
			htmlspecialchars($row['database']), " · <span class=\"vault-mono\">", htmlspecialchars($row['pg_username']), "</span></p>\n";
		echo "<div class=\"vault-field\"><label for=\"vault-label\">", htmlspecialchars($lang['strvaultlabel']), "</label>",
			"<input type=\"text\" id=\"vault-label\" name=\"label\" maxlength=\"100\" size=\"40\" required=\"required\" value=\"", htmlspecialchars($label), "\" /></div>\n";
		echo "<fieldset class=\"vault-access\"><legend>", htmlspecialchars($lang['strvaultaccess']), "</legend>\n";
		foreach (array('read-only' => $lang['strvaultreadonly'], 'read-write' => $lang['strvaultreadwrite']) as $value => $text) {
			echo "<label><input type=\"radio\" name=\"access\" value=\"{$value}\"", $access === $value ? ' checked="checked"' : '', " /> ",
				htmlspecialchars($text), "</label>\n";
		}
		echo "</fieldset>\n";
		echo "<p class=\"vault-hint\">", htmlspecialchars($lang['strvaultaccesshint']), "</p>\n";
		echo "<input type=\"hidden\" name=\"action\" value=\"saverename\" />\n";
		echo "<input type=\"hidden\" name=\"id\" value=\"", htmlspecialchars($vault_id), "\" />\n";
		echo $misc->form;
		vaultButtons($lang['strsave']);
		echo "</form>\n";
	}

	function doSaveRename() {
		global $vault, $vault_who, $vault_id, $lang;

		$label = isset($_POST['label']) && is_scalar($_POST['label']) ? (string) $_POST['label'] : '';
		$access = isset($_POST['access']) && is_scalar($_POST['access']) ? (string) $_POST['access'] : '';
		try {
			$vault->creds->rename($vault_who, $vault_id, $label, $access);
		} catch (VaultError $e) {
			doDefault(vaultErrorText($e), true);
			return;
		} catch (PDOException $e) {
			error_log('phpPgAdmin: the vault database failed: ' . $e->getMessage());
			doDefault($lang['strvaultstorefailed'], true);
			return;
		}
		doDefault(sprintf($lang['strvaultrenamed'], trim($label)));
	}

	function doPassword() {
		global $misc, $lang, $vault_id;

		$row = vaultFormPage($vault_id, $lang['strvaultupdatepassword']);
		if ($row === null) return;

		echo "<form action=\"vault.php\" method=\"post\" class=\"vault-form\" autocomplete=\"off\">\n";
		echo "<p class=\"vault-where\"><strong>", htmlspecialchars($row['label']), "</strong> · ",
			htmlspecialchars(vaultServerName($row['server_id'])), " · ", htmlspecialchars($row['database']),
			" · <span class=\"vault-mono\">", htmlspecialchars($row['pg_username']), "</span></p>\n";
		echo "<div class=\"vault-field\"><label for=\"vault-password\">", htmlspecialchars($lang['strvaultnewpassword']), "</label>",
			"<input type=\"password\" id=\"vault-password\" name=\"password\" autocomplete=\"new-password\" size=\"30\" required=\"required\" value=\"\" /></div>\n";
		echo "<p class=\"vault-hint\">", htmlspecialchars($lang['strvaultpasswordhint']), "</p>\n";
		echo "<input type=\"hidden\" name=\"action\" value=\"savepassword\" />\n";
		echo "<input type=\"hidden\" name=\"id\" value=\"", htmlspecialchars($vault_id), "\" />\n";
		echo $misc->form;
		vaultButtons($lang['strsave']);
		echo "</form>\n";
	}

	function doSavePassword() {
		global $vault, $vault_who, $vault_id, $lang, $conf;

		$password = isset($_POST['password']) && is_scalar($_POST['password']) ? (string) $_POST['password'] : '';
		try {
			$row = vaultMyLogin($vault_id);
			$server = $row !== null ? $vault->servers->get($row['server_id']) : null;
			if ($row === null || $server === null || $server['status'] !== 'active') {
				throw new VaultError('strvaultnotfound');
			}
			if ($password === '' || strlen($password) > 1000) {
				throw new VaultError('strvaultbadpassword');
			}
			// Trying passwords here counts like logging in: the same lock,
			// and a wrong one is a login_failed row that counts toward it.
			$lock = $vault->audit->loginLockSeconds($vault_who->username, $row['server_id'], time());
			if ($lock > 0) {
				doDefault(Vault::loginLockMessage($lock), true);
				return;
			}
			// What the connection settings of this server say (env servers may
			// carry a root certificate the table doesn't).
			$target = array('host' => $server['host'], 'port' => $server['port'], 'sslmode' => $server['sslmode']);
			foreach ((isset($conf['servers']) && is_array($conf['servers'])) ? $conf['servers'] : array() as $candidate) {
				if (isset($candidate['key']) && $candidate['key'] === $row['server_id']) {
					foreach (array('host', 'port', 'sslmode', 'sslrootcert') as $field) {
						if (isset($candidate[$field])) $target[$field] = $candidate[$field];
					}
					break;
				}
			}
			$result = VaultConnect::test($target, $row['database'], $row['pg_username'], $password, Vault::appName($vault_who->username));
			if (!$result['ok']) {
				$vault->audit->log($vault_who->username, VaultAudit::LOGIN_FAILED, array(
					'credential_id' => $row['id'],
					'server_id' => $row['server_id'],
					'database' => $row['database'],
					'detail' => array('pg_username' => $row['pg_username'], 'reason' => $result['reason_key']),
				));
				doDefault(sprintf($lang['strvaultpasswordkept'], $row['label']) . ' ' . $result['reason'], true);
				return;
			}
			$vault->creds->updatePassword($vault_who, $vault_id, $password);
		} catch (VaultError $e) {
			doDefault(vaultErrorText($e), true);
			return;
		} catch (PDOException $e) {
			error_log('phpPgAdmin: the vault database failed: ' . $e->getMessage());
			doDefault($lang['strvaultstorefailed'], true);
			return;
		}
		doDefault(sprintf($lang['strvaultpasswordupdated'], $row['label']));
	}

	function doDelete() {
		global $misc, $lang, $vault_id;

		$row = vaultFormPage($vault_id, $lang['strdelete']);
		if ($row === null) return;

		echo "<form action=\"vault.php\" method=\"post\" class=\"vault-form\">\n";
		echo "<p>", htmlspecialchars(sprintf($lang['strvaultconfdelete'], $row['label'])), "</p>\n";
		echo "<p class=\"vault-where\">", htmlspecialchars(vaultServerName($row['server_id'])), " · ",
			htmlspecialchars($row['database']), " · <span class=\"vault-mono\">", htmlspecialchars($row['pg_username']), "</span></p>\n";
		echo "<input type=\"hidden\" name=\"action\" value=\"dodelete\" />\n";
		echo "<input type=\"hidden\" name=\"id\" value=\"", htmlspecialchars($vault_id), "\" />\n";
		echo $misc->form;
		vaultButtons($lang['strdelete']);
		echo "</form>\n";
	}

	function doDoDelete() {
		global $vault, $vault_who, $vault_id, $lang;

		try {
			$row = vaultMyLogin($vault_id);
			if ($row === null) throw new VaultError('strvaultnotfound');
			$vault->creds->delete($vault_who, $vault_id);
		} catch (VaultError $e) {
			doDefault(vaultErrorText($e), true);
			return;
		} catch (PDOException $e) {
			error_log('phpPgAdmin: the vault database failed: ' . $e->getMessage());
			doDefault($lang['strvaultstorefailed'], true);
			return;
		}
		doDefault(sprintf($lang['strvaultdeleted'], $row['label']));
	}

	$misc->printHeader($lang['strvaultmylogins']);
	$misc->printBody();

	// A GET never changes anything; the save actions need a POST, and
	// lib.inc.php has already checked its token.
	if (isset($_POST['cancel'])) $action = '';
	if (!Misc::isPost() && in_array($action, array('saverename', 'savepassword', 'dodelete'), true)) $action = '';

	switch ($action) {
		case 'rename':
			doRename();
			break;
		case 'saverename':
			doSaveRename();
			break;
		case 'password':
			doPassword();
			break;
		case 'savepassword':
			doSavePassword();
			break;
		case 'delete':
			doDelete();
			break;
		case 'dodelete':
			doDoDelete();
			break;
		default:
			doDefault();
			break;
	}

	$misc->printFooter();

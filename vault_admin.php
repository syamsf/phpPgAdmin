<?php

	/**
	 * Shared logins (board 4), admins only: the shared logins by server,
	 * the sharing panel of one login (share with a user or group, with an
	 * optional expiry; remove a share; recent activity), delete, and the
	 * audit log. No shared password is ever shown here, to admins
	 * included, and other people's personal logins are never named.
	 */

	// Not tied to a server
	$_no_db_connection = true;
	include_once('./libraries/lib.inc.php');

	if (!isset($vault) || !($vault instanceof Vault)) {
		echo htmlspecialchars($lang['strvaultnouser']);
		exit;
	}
	$vault->requireAdmin();

	$action = (isset($_REQUEST['action']) && is_scalar($_REQUEST['action'])) ? (string) $_REQUEST['action'] : '';
	$vault_id = (isset($_REQUEST['id']) && is_scalar($_REQUEST['id'])) ? (string) $_REQUEST['id'] : '';
	// What was typed in the share form, shown again after an error.
	$vault_share_form = array('type' => 'group', 'principal' => '', 'expires' => '');

	/** Rows per audit page. */
	const VAULT_AUDIT_PAGE = 100;

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

	function vaultPost($name) {
		return (isset($_POST[$name]) && is_scalar($_POST[$name])) ? (string) $_POST[$name] : '';
	}

	function vaultGetParam($name) {
		return (isset($_GET[$name]) && is_scalar($_GET[$name])) ? (string) $_GET[$name] : '';
	}

	function vaultStoreFailed(PDOException $e) {
		global $lang;
		error_log('phpPgAdmin: the vault database failed: ' . $e->getMessage());
		return $lang['strvaultstorefailed'];
	}

	function vaultTag($access) {
		global $lang;
		return '<span class="vault-tag ' . ($access === 'read-only' ? 'vault-tag-ro' : 'vault-tag-rw') . '">'
			. htmlspecialchars($access === 'read-only' ? $lang['strvaultreadonly'] : $lang['strvaultreadwrite']) . '</span>';
	}

	/** One shared login (no password fields), or null for anything else. */
	function vaultSharedLogin($id) {
		global $vault;
		if ($id === '') return null;
		$row = $vault->creds->get($vault->identity, $id);
		return ($row !== null && $row['kind'] === 'shared') ? $row : null;
	}

	/** A server's name for display, by its vault key. */
	function vaultServerName($key) {
		global $vault;
		static $names = array();
		if ($key === null || $key === '') return '';
		if (!array_key_exists($key, $names)) {
			$server = $vault->servers->get($key);
			$names[$key] = ($server !== null && $server['name'] !== '') ? $server['name'] : $key;
		}
		return $names[$key];
	}

	function vaultStatus($row) {
		global $lang;
		if ($row['server_status'] === 'removed') {
			$key = 'strvaultserverremoved';
		} elseif ($row['server_status'] === 'disabled') {
			$key = 'strvaultserverdisabled';
		} elseif ($row['last_status'] === 'auth_failed') {
			$key = 'strvaultpasswordfailed';
		} else {
			return '<span class="vault-status vault-status-ok">' . htmlspecialchars($lang['strvaultok']) . '</span>';
		}
		return '<span class="vault-status vault-status-failed">' . htmlspecialchars($lang[$key]) . '</span>';
	}

	/** "<strong>alice</strong> used it", for the panel's recent activity. HTML. */
	function vaultActivity($row) {
		global $lang;
		$actor = '<strong>' . htmlspecialchars($row['actor']) . '</strong>';
		$detail = json_decode((string) $row['detail'], true);
		$principal = (is_array($detail) && isset($detail['principal']) && is_scalar($detail['principal']))
			? htmlspecialchars((string) $detail['principal']) : '';
		$keys = array(
			VaultAudit::LOGIN_USED => 'strvaultactused',
			VaultAudit::LOGIN_FAILED => 'strvaultactfailed',
			VaultAudit::SHARE_ADDED => 'strvaultactshared',
			VaultAudit::SHARE_REMOVED => 'strvaultactunshared',
			VaultAudit::PASSWORD_UPDATED => 'strvaultactpassword',
			VaultAudit::CREDENTIAL_CHANGED => 'strvaultactchanged',
			VaultAudit::LOGIN_SAVED => 'strvaultactcreated',
		);
		if (isset($keys[$row['action']])) {
			return sprintf(htmlspecialchars($lang[$keys[$row['action']]]), $actor, $principal);
		}
		return sprintf(htmlspecialchars($lang['strvaultactother']), $actor, htmlspecialchars($row['action']));
	}

	/** "expires 15 Dec 2026 · added by boss" for one share. */
	function vaultShareMeta($share, $now) {
		global $lang;
		if ($share['expires_at'] === null) {
			$when = $lang['strvaultmetanoexpiry'];
		} elseif ($share['expires_at'] <= $now) {
			$when = sprintf($lang['strvaultexpired'], VaultFormat::date($share['expires_at']));
		} else {
			$when = sprintf($lang['strvaultmetaexpires'], VaultFormat::date($share['expires_at']));
		}
		return $when . ' · ' . sprintf($lang['strvaultaddedby'], $share['granted_by']);
	}

	function vaultButtons($doLabel) {
		global $lang;
		echo "<p><input type=\"submit\" class=\"vault-primary\" value=\"", htmlspecialchars($doLabel), "\" /> ",
			"<input type=\"submit\" name=\"cancel\" value=\"", htmlspecialchars($lang['strcancel']), "\" formnovalidate=\"formnovalidate\" /></p>\n";
	}

	/**
	 * The list of shared logins, with the sharing panel of $vault_id when
	 * it is one of them.
	 */
	function doDefault($msg = '', $error = false) {
		global $misc, $lang, $vault, $vault_id;

		$misc->printTrail('root');
		$misc->printTabs('root', 'shared');
		vaultMsg($msg, $error);

		$rows = array();
		try {
			$rows = $vault->creds->sharedAll();
		} catch (PDOException $e) {
			vaultMsg(vaultStoreFailed($e), true);
		}
		$selected = null;
		foreach ($rows as $row) {
			if ($row['id'] === $vault_id) $selected = $row;
		}
		if ($vault_id !== '' && $selected === null && $msg === '') {
			vaultMsg($lang['strvaultnotfound'], true);
		}

		echo "<div class=\"vault-page vault-admin\">\n";
		echo "<div class=\"vault-admin-head\">\n<div>\n";
		echo "<h2>", htmlspecialchars($lang['strvaultsharedlogins']), "</h2>\n";
		echo "<p class=\"vault-intro\">", htmlspecialchars($lang['strvaultsharedintro']), "</p>\n";
		echo "</div>\n<a href=\"vault_admin.php?action=edit\" class=\"vault-button\">", htmlspecialchars($lang['strvaultnewshared']), "</a>\n";
		echo "</div>\n";

		echo "<div class=\"vault-admin-body\">\n";
		echo "<section class=\"vault-admin-list\" aria-label=\"", htmlspecialchars($lang['strvaultsharedlogins']), "\">\n";
		if ($rows) {
			$counts = array();
			foreach ($rows as $row) {
				$counts[$row['server_id']] = ($counts[$row['server_id']] ?? 0) + 1;
			}
			echo "<div class=\"vault-table-wrap\">\n<table class=\"vault-table\">\n<thead><tr>";
			foreach (array('strvaultlabel', 'strdatabase', 'strvaultpguser', 'strvaultaccess', 'strvaultsharedwith', 'strvaultstatus') as $key) {
				echo "<th scope=\"col\">", htmlspecialchars($lang[$key]), "</th>";
			}
			echo "</tr></thead>\n<tbody>\n";
			$current = null;
			foreach ($rows as $row) {
				if ($row['server_id'] !== $current) {
					$current = $row['server_id'];
					$n = $counts[$current];
					echo "<tr><th scope=\"colgroup\" colspan=\"6\" class=\"vault-group\">", htmlspecialchars($row['server_name']),
						" <span>· ", htmlspecialchars($lang[$row['server_source'] === 'env' ? 'strvaultsourceenv' : 'strvaultsourceui']),
						" · ", htmlspecialchars($n === 1 ? $lang['strvaultonesharedlogin'] : sprintf($lang['strvaultnsharedlogins'], $n)),
						"</span></th></tr>\n";
				}
				$classes = array();
				if ($selected !== null && $row['id'] === $selected['id']) $classes[] = 'vault-row-selected';
				elseif ($row['last_status'] === 'auth_failed' || $row['server_status'] !== 'active') $classes[] = 'vault-row-failed';
				echo "<tr", $classes ? ' class="' . implode(' ', $classes) . '"' : '', ">\n";
				echo "<td class=\"vault-label\"><a href=\"vault_admin.php?id=", rawurlencode($row['id']), "\"",
					($selected !== null && $row['id'] === $selected['id']) ? ' aria-current="true"' : '', ">",
					htmlspecialchars($row['label']), "</a></td>\n";
				echo "<td>", htmlspecialchars($row['database']), "</td>\n";
				echo "<td class=\"vault-mono\">", htmlspecialchars($row['pg_username']), "</td>\n";
				echo "<td>", vaultTag($row['access_label']), "</td>\n";
				echo "<td", $row['summary'] === $lang['strvaultnotshared'] ? ' class="vault-muted"' : '', ">",
					htmlspecialchars($row['summary']), "</td>\n";
				echo "<td>", vaultStatus($row), "</td>\n";
				echo "</tr>\n";
			}
			echo "</tbody>\n</table>\n</div>\n";
		} else {
			echo "<p>", htmlspecialchars($lang['strvaultnoshared']), "</p>\n";
		}
		echo "<p class=\"vault-note\">", htmlspecialchars($lang['strvaultstatusnote']), "</p>\n";
		echo "</section>\n";

		if ($selected !== null) {
			vaultPanel($selected);
		}
		echo "</div>\n</div>\n";
	}

	/** The sharing panel of one shared login (a row of sharedAll()). */
	function vaultPanel($row) {
		global $misc, $lang, $vault, $vault_share_form;

		$id = $row['id'];
		$shares = array();
		$activity = array();
		$users = array();
		$groups = array();
		try {
			$shares = $vault->creds->shares($id);
			$activity = $vault->audit->forCredential($id, 5);
			foreach ($vault->users->all() as $user) {
				$users[$user['username']] = true;
				foreach ($user['groups'] as $group) $groups[$group] = true;
			}
			foreach ($vault->creds->groupPrincipals() as $group) $groups[$group] = true;
		} catch (PDOException $e) {
			vaultMsg(vaultStoreFailed($e), true);
		}
		ksort($groups, SORT_STRING);
		$now = VaultStore::now();
		$nowTs = time();
		$active = 0;
		foreach ($shares as $share) {
			if ($share['expires_at'] === null || $share['expires_at'] > $now) $active++;
		}
		$e = rawurlencode($id);
		$isUser = $vault_share_form['type'] === 'user';

		echo "<aside class=\"vault-panel\" aria-labelledby=\"vault-panel-h\">\n";
		echo "<div class=\"vault-panel-head\">\n<h3 id=\"vault-panel-h\">", htmlspecialchars(sprintf($lang['strvaultsharing'], $row['label'])), "</h3>\n";
		echo "<p>", htmlspecialchars($row['server_name']), " / ", htmlspecialchars($row['database']), " · ",
			"<span class=\"vault-mono\">", htmlspecialchars($row['pg_username']), "</span></p>\n</div>\n";

		// Share form
		echo "<form action=\"vault_admin.php\" method=\"post\" class=\"vault-panel-part vault-share-form\" autocomplete=\"off\">\n";
		echo "<fieldset class=\"vault-access\"><legend>", htmlspecialchars($lang['strvaultsharewith']), "</legend>\n";
		foreach (array('group' => array('strvaultgroup', 'strvaultprincipalgroup'), 'user' => array('strvaultuser', 'strvaultprincipaluser')) as $type => $keys) {
			echo "<label><input type=\"radio\" name=\"type\" value=\"{$type}\" data-vault-share-type=\"\" data-label=\"",
				htmlspecialchars($lang[$keys[1]]), "\"", ($isUser === ($type === 'user')) ? ' checked="checked"' : '', " /> ",
				htmlspecialchars($lang[$keys[0]]), "</label>\n";
		}
		echo "</fieldset>\n";
		echo "<div class=\"vault-field\"><label for=\"vault-principal\">",
			htmlspecialchars($lang[$isUser ? 'strvaultprincipaluser' : 'strvaultprincipalgroup']), "</label>",
			"<input type=\"text\" id=\"vault-principal\" name=\"principal\" list=\"vault-principals\" maxlength=\"128\" required=\"required\" placeholder=\"",
			htmlspecialchars($lang['strvaultprincipalplaceholder']), "\" value=\"", htmlspecialchars($vault_share_form['principal']), "\" /></div>\n";
		echo "<datalist id=\"vault-principals\">\n";
		foreach (array_keys($groups) as $group) {
			echo "<option value=\"", htmlspecialchars((string) $group), "\" label=\"", htmlspecialchars($lang['strvaultsharegroup']), "\"></option>\n";
		}
		foreach (array_keys($users) as $user) {
			echo "<option value=\"", htmlspecialchars((string) $user), "\" label=\"", htmlspecialchars($lang['strvaultshareuser']), "\"></option>\n";
		}
		echo "</datalist>\n";
		echo "<div class=\"vault-field\"><label for=\"vault-expires\">", htmlspecialchars($lang['strvaultexpiresoptional']), "</label>",
			"<input type=\"date\" id=\"vault-expires\" name=\"expires\" min=\"", gmdate('Y-m-d'), "\" value=\"",
			htmlspecialchars($vault_share_form['expires']), "\" /></div>\n";
		echo "<input type=\"hidden\" name=\"action\" value=\"share\" />\n";
		echo "<input type=\"hidden\" name=\"id\" value=\"", htmlspecialchars($id), "\" />\n";
		echo $misc->form;
		echo "<p><input type=\"submit\" class=\"vault-primary\" value=\"", htmlspecialchars($lang['strvaultadd']), "\" /></p>\n";
		echo "</form>\n";

		// Who has it
		echo "<div class=\"vault-panel-part\">\n<h4>", htmlspecialchars(sprintf($lang['strvaulthasaccess'], $active)), "</h4>\n";
		if ($shares) {
			echo "<ul class=\"vault-shares\">\n";
			foreach ($shares as $share) {
				$expired = $share['expires_at'] !== null && $share['expires_at'] <= $now;
				echo "<li", $expired ? ' class="vault-share-expired"' : '', ">\n<span class=\"vault-share-who\"><span><span class=\"vault-muted\">",
					htmlspecialchars($lang[$share['principal_type'] === 'group' ? 'strvaultsharegroup' : 'strvaultshareuser']), "</span> <strong>",
					htmlspecialchars($share['principal']), "</strong></span><span class=\"vault-share-meta",
					$share['expires_at'] !== null ? ' vault-expires' : '', "\">", htmlspecialchars(vaultShareMeta($share, $now)), "</span></span>\n";
				echo "<form action=\"vault_admin.php\" method=\"post\">",
					"<input type=\"hidden\" name=\"action\" value=\"unshare\" />",
					"<input type=\"hidden\" name=\"id\" value=\"", htmlspecialchars($id), "\" />",
					"<input type=\"hidden\" name=\"type\" value=\"", htmlspecialchars($share['principal_type']), "\" />",
					"<input type=\"hidden\" name=\"principal\" value=\"", htmlspecialchars($share['principal']), "\" />",
					$misc->form,
					"<input type=\"submit\" class=\"vault-remove\" value=\"", htmlspecialchars($lang['strvaultremove']), "\" ",
					"aria-label=\"", htmlspecialchars($lang['strvaultremove'] . ' ' . $share['principal']), "\" /></form>\n";
				echo "</li>\n";
			}
			echo "</ul>\n";
		}
		echo "</div>\n";

		// Recent activity
		echo "<div class=\"vault-panel-part\">\n<h4>", htmlspecialchars($lang['strvaultrecent']), "</h4>\n";
		if ($activity) {
			echo "<ul class=\"vault-activity\">\n";
			foreach ($activity as $a) {
				echo "<li>", vaultActivity($a), " · ", htmlspecialchars(VaultFormat::ago($a['at'], $nowTs)), "</li>\n";
			}
			echo "</ul>\n";
		} else {
			echo "<p class=\"vault-muted\">", htmlspecialchars($lang['strvaultnoactivity']), "</p>\n";
		}
		echo "<p><a href=\"vault_admin.php?action=audit&amp;credential_id={$e}\" class=\"vault-note\">", htmlspecialchars($lang['strvaultfullaudit']), "</a></p>\n";
		echo "</div>\n";

		echo "<p class=\"vault-panel-part vault-panel-links\">",
			"<a href=\"vault_admin.php?action=edit&amp;id={$e}\">", htmlspecialchars($lang['strvaulteditlogin']), "</a> ",
			"<a href=\"vault_admin.php?action=edit&amp;id={$e}#vault-password\">", htmlspecialchars($lang['strvaultreplacepassword']), "</a> ",
			"<a href=\"vault_admin.php?action=delete&amp;id={$e}\" data-ppa-dialog=\"modal\" class=\"vault-delete-link\">", htmlspecialchars($lang['strvaultdeleteshared']), "</a>",
			"</p>\n";
		echo "</aside>\n";
	}

	function vaultTypeWord($type) {
		global $lang;
		return $lang[$type === 'group' ? 'strvaultsharegroup' : 'strvaultshareuser'];
	}

	function doShare() {
		global $vault, $vault_id, $vault_share_form, $lang;

		$type = vaultPost('type');
		$principal = vaultPost('principal');
		$expires = trim(vaultPost('expires'));
		$vault_share_form = array('type' => $type === 'user' ? 'user' : 'group', 'principal' => $principal, 'expires' => $expires);
		try {
			$vault->creds->share($vault->identity, $vault_id, $type, $principal, $expires === '' ? null : $expires);
		} catch (VaultError $e) {
			doDefault(vaultErrorText($e), true);
			return;
		} catch (PDOException $e) {
			doDefault(vaultStoreFailed($e), true);
			return;
		}
		$vault_share_form = array('type' => $type, 'principal' => '', 'expires' => '');
		doDefault(sprintf($lang['strvaultshareadded'], vaultTypeWord($type), trim($principal)));
	}

	function doUnshare() {
		global $vault, $vault_id, $lang;

		$type = vaultPost('type');
		$principal = vaultPost('principal');
		try {
			$vault->creds->unshare($vault->identity, $vault_id, $type, $principal);
		} catch (VaultError $e) {
			doDefault(vaultErrorText($e), true);
			return;
		} catch (PDOException $e) {
			doDefault(vaultStoreFailed($e), true);
			return;
		}
		doDefault(sprintf($lang['strvaultshareremoved'], vaultTypeWord($type), $principal));
	}

	function doDelete() {
		global $misc, $lang, $vault_id;

		$row = vaultSharedLogin($vault_id);
		if ($row === null) {
			doDefault($lang['strvaultnotfound'], true);
			return;
		}
		$misc->printTrail('root');
		$misc->printTitle($lang['strvaultdeleteshared']);
		echo "<form action=\"vault_admin.php\" method=\"post\" class=\"vault-form\">\n";
		echo "<p>", htmlspecialchars(sprintf($lang['strvaultconfdeleteshared'], $row['label'])), "</p>\n";
		echo "<p class=\"vault-where\">", htmlspecialchars(vaultServerName($row['server_id'])), " / ",
			htmlspecialchars($row['database']), " · <span class=\"vault-mono\">", htmlspecialchars($row['pg_username']), "</span></p>\n";
		echo "<input type=\"hidden\" name=\"action\" value=\"dodelete\" />\n";
		echo "<input type=\"hidden\" name=\"id\" value=\"", htmlspecialchars($vault_id), "\" />\n";
		echo $misc->form;
		vaultButtons($lang['strdelete']);
		echo "</form>\n";
	}

	function doDoDelete() {
		global $vault, $vault_id, $lang;

		try {
			$row = vaultSharedLogin($vault_id);
			if ($row === null) throw new VaultError('strvaultnotfound');
			$vault->creds->delete($vault->identity, $vault_id);
		} catch (VaultError $e) {
			$vault_id = '';
			doDefault(vaultErrorText($e), true);
			return;
		} catch (PDOException $e) {
			doDefault(vaultStoreFailed($e), true);
			return;
		}
		$vault_id = '';
		doDefault(sprintf($lang['strvaultshareddeleted'], $row['label']));
	}

	/** One audit detail as "key: value" lines. HTML. */
	function vaultDetail($json) {
		$detail = json_decode((string) $json, true);
		if (!is_array($detail) || !$detail) return '';
		$out = array();
		foreach ($detail as $key => $value) {
			if (is_array($value)) {
				$scalar = true;
				foreach ($value as $item) $scalar = $scalar && (is_scalar($item) || $item === null);
				$value = $scalar ? implode(', ', array_map('strval', $value)) : json_encode($value, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
			} elseif (is_bool($value)) {
				$value = $value ? 'true' : 'false';
			} elseif ($value === null) {
				$value = '—';
			}
			$out[] = '<span class="vault-kv">' . htmlspecialchars($key . ': ' . $value) . '</span>';
		}
		return implode(' ', $out);
	}

	function vaultAuditUrl(array $params) {
		$params = array_filter($params, function ($v) { return $v !== '' && $v !== null; });
		return 'vault_admin.php?' . htmlspecialchars(http_build_query(array_merge(array('action' => 'audit'), $params), '', '&'));
	}

	function doAudit() {
		global $misc, $lang, $vault;

		$filter = array(
			'credential_id' => vaultGetParam('credential_id'),
			'actor' => vaultGetParam('actor'),
			'action' => vaultGetParam('action_filter'),
		);
		$before = vaultGetParam('before');
		$beforeId = preg_match('/^[1-9][0-9]{0,18}$/D', $before) ? (int) $before : null;

		$misc->printTrail('root');
		$misc->printTabs('root', 'shared');

		$rows = array();
		try {
			$rows = $vault->audit->page($filter, $beforeId, VAULT_AUDIT_PAGE + 1);
		} catch (PDOException $e) {
			vaultMsg(vaultStoreFailed($e), true);
		}
		$more = count($rows) > VAULT_AUDIT_PAGE;
		$rows = array_slice($rows, 0, VAULT_AUDIT_PAGE);

		echo "<div class=\"vault-page\">\n";
		echo "<h2>", htmlspecialchars($lang['strvaultaudit']), "</h2>\n";
		echo "<p class=\"vault-intro\">", htmlspecialchars($lang['strvaultauditintro']), "</p>\n";

		// Filters (a GET form: it only narrows what is shown)
		$actions = array(
			VaultAudit::LOGIN_SAVED, VaultAudit::LOGIN_USED, VaultAudit::LOGIN_FAILED, VaultAudit::SHARE_ADDED,
			VaultAudit::SHARE_REMOVED, VaultAudit::PASSWORD_UPDATED, VaultAudit::CREDENTIAL_CHANGED,
			VaultAudit::CREDENTIAL_DELETED, VaultAudit::USER_ADDED, VaultAudit::USER_DISABLED, VaultAudit::USER_ENABLED,
			VaultAudit::PASSWORD_RESET, VaultAudit::GROUPS_CHANGED, VaultAudit::SIGNIN_FAILED, VaultAudit::SERVER_ADDED,
			VaultAudit::SERVER_CHANGED, VaultAudit::SERVER_DELETED,
		);
		echo "<form action=\"vault_admin.php\" method=\"get\" class=\"vault-audit-filter\">\n";
		echo "<input type=\"hidden\" name=\"action\" value=\"audit\" />\n";
		if ($filter['credential_id'] !== '') {
			echo "<input type=\"hidden\" name=\"credential_id\" value=\"", htmlspecialchars($filter['credential_id']), "\" />\n";
		}
		echo "<div class=\"vault-field\"><label for=\"vault-actor\">", htmlspecialchars($lang['strvaultwho']), "</label>",
			"<input type=\"text\" id=\"vault-actor\" name=\"actor\" maxlength=\"128\" value=\"", htmlspecialchars($filter['actor']), "\" /></div>\n";
		echo "<div class=\"vault-field\"><label for=\"vault-action\">", htmlspecialchars($lang['strvaultaction']), "</label>",
			"<select id=\"vault-action\" name=\"action_filter\">\n<option value=\"\">", htmlspecialchars($lang['strvaultallactions']), "</option>\n";
		foreach ($actions as $a) {
			echo "<option value=\"{$a}\"", $filter['action'] === $a ? ' selected="selected"' : '', ">{$a}</option>\n";
		}
		echo "</select></div>\n";
		echo "<p><input type=\"submit\" value=\"", htmlspecialchars($lang['strvaultfilter']), "\" /></p>\n";
		echo "</form>\n";

		if ($filter['credential_id'] !== '') {
			$name = $lang['strvaultdeletedlogin'];
			foreach ($rows as $row) {
				$name = vaultLoginName($row);
				break;
			}
			echo "<p>", htmlspecialchars(sprintf($lang['strvaultforlogin'], $name)), " · <a href=\"",
				vaultAuditUrl(array('actor' => $filter['actor'], 'action_filter' => $filter['action'])), "\">",
				htmlspecialchars($lang['strvaultallrows']), "</a></p>\n";
		}

		if ($rows) {
			echo "<div class=\"vault-table-wrap\">\n<table class=\"vault-table vault-audit\">\n<thead><tr>";
			foreach (array('strvaultwhen', 'strvaultwho', 'strvaultaction', 'strvaultlogincol', 'strvaultserverdb', 'strvaultip', 'strvaultdetail') as $key) {
				echo "<th scope=\"col\">", htmlspecialchars($lang[$key]), "</th>";
			}
			echo "</tr></thead>\n<tbody>\n";
			foreach ($rows as $row) {
				$ts = strtotime($row['at']);
				echo "<tr>\n";
				echo "<td class=\"vault-nowrap\"><time datetime=\"", htmlspecialchars($row['at']), "\">",
					htmlspecialchars($ts === false ? $row['at'] : gmdate('j M Y H:i:s', $ts)), "</time></td>\n";
				echo "<td>", htmlspecialchars($row['actor']), "</td>\n";
				echo "<td class=\"vault-mono\">", htmlspecialchars($row['action']), "</td>\n";
				echo "<td>";
				if ($row['login'] === 'shared') {
					echo "<a href=\"vault_admin.php?id=", rawurlencode((string) $row['credential_id']), "\">", htmlspecialchars((string) $row['label']), "</a>";
				} elseif ($row['login'] !== 'none') {
					echo "<span class=\"vault-muted\">", htmlspecialchars(vaultLoginName($row)), "</span>";
				}
				echo "</td>\n";
				$where = vaultServerName($row['server_id']);
				if ($row['database'] !== null && $row['database'] !== '') $where .= ' / ' . $row['database'];
				echo "<td>", htmlspecialchars($where), "</td>\n";
				echo "<td class=\"vault-mono\">", htmlspecialchars((string) $row['client_ip']), "</td>\n";
				echo "<td class=\"vault-detail\">", vaultDetail($row['detail']), "</td>\n";
				echo "</tr>\n";
			}
			echo "</tbody>\n</table>\n</div>\n";
		} else {
			echo "<p>", htmlspecialchars($lang['strvaultnoaudit']), "</p>\n";
		}
		if ($more) {
			$last = end($rows);
			echo "<p><a href=\"", vaultAuditUrl(array('credential_id' => $filter['credential_id'], 'actor' => $filter['actor'],
				'action_filter' => $filter['action'], 'before' => (string) $last['id'])), "\">", htmlspecialchars($lang['strvaultolder']), "</a></p>\n";
		}
		echo "</div>\n";
	}

	/** The Login column's text: a shared login's label, else "personal login" or "deleted login". */
	function vaultLoginName($row) {
		global $lang;
		if ($row['login'] === 'shared') return (string) $row['label'];
		if ($row['login'] === 'personal') return $lang['strvaultpersonallogin'];
		if ($row['login'] === 'deleted') return $lang['strvaultdeletedlogin'];
		return '';
	}

	/** The $conf['servers'] entry of a vault server key, or null (UI servers are in it too). */
	function vaultConfServer($key) {
		global $conf;
		foreach ((isset($conf['servers']) && is_array($conf['servers'])) ? $conf['servers'] : array() as $candidate) {
			if (isset($candidate['key']) && $candidate['key'] === $key) return $candidate;
		}
		return null;
	}

	/** The databases a per-database server allows, or an empty list when any is fine. */
	function vaultAllowedDatabases($key) {
		$server = vaultConfServer($key);
		if ($server === null || empty($server['databases']) || !is_array($server['databases'])) return array();
		return array_map('strval', array_values($server['databases']));
	}

	/** What the form posted, minus nothing: the password is read separately and never echoed. */
	function vaultReadSharedForm() {
		return array(
			'server_id' => vaultPost('server_id'),
			'database' => trim(vaultPost('database')),
			'label' => trim(vaultPost('label')),
			'pg_username' => trim(vaultPost('pg_username')),
			'access_label' => vaultPost('access_label'),
			'password' => vaultPost('password'),
		);
	}

	/**
	 * Tests the connection with what was typed (or the stored password when
	 * the password is blank and nothing that it belongs to changed), after
	 * the same checks saving does.
	 * @param string $id the login being edited, '' for a new one
	 * @return array the VaultConnect::test() result
	 * @throws VaultError a field is wrong or the stored password can't be read
	 */
	function vaultTestShared($id, array $f) {
		global $vault;

		$vault->creds->checkShared($f, $id === '' ? null : $id);
		$allowed = vaultAllowedDatabases($f['server_id']);
		if ($allowed && !in_array($f['database'], $allowed, true)) {
			global $lang;
			throw new VaultError(sprintf($lang['strvaultdbnotonserver'], implode(', ', $allowed)));
		}
		$password = $f['password'] !== '' ? $f['password'] : $vault->creds->sharedPassword($vault->identity, $id);
		$server = $vault->servers->get($f['server_id']);
		if ($server === null) throw new VaultError('strvaultnotfound');
		$target = array('host' => $server['host'], 'port' => $server['port'], 'sslmode' => $server['sslmode']);
		$candidate = vaultConfServer($f['server_id']);
		if ($candidate !== null) {
			foreach (array('host', 'port', 'sslmode', 'sslrootcert') as $field) {
				if (isset($candidate[$field])) $target[$field] = $candidate[$field];
			}
		}
		return VaultConnect::test($target, $f['database'], $f['pg_username'], $password, Vault::appName($vault->identity->username));
	}

	/** The login form (new when $id is ''). $result is the test's outcome line: array(text, ok). */
	function vaultSharedForm($id, array $f, $result = null) {
		global $misc, $lang, $vault;

		$servers = $vault->servers->active();
		if (empty($vault->config['servers_allow_ui'])) {
			// SERVERS_ALLOW_UI=false: UI servers are off, so not offered here.
			$servers = array_values(array_filter($servers, function ($s) { return $s['source'] !== 'ui'; }));
		}
		$known = false;
		foreach ($servers as $s) {
			if ($s['key'] === $f['server_id']) $known = true;
		}
		if (!$known && $f['server_id'] !== '') {
			// A login whose server is no longer active still shows where it is.
			$current = $vault->servers->get($f['server_id']);
			if ($current !== null) array_unshift($servers, $current);
		}
		if ($f['server_id'] === '' && $servers) $f['server_id'] = $servers[0]['key'];

		$misc->printTrail('root');
		$crumb = $id === '' ? $lang['strvaultbreadnew'] : $f['label'] . ' › ' . $lang['strvaultbreadedit'];
		echo "<div class=\"vault-crumb\"><a href=\"vault_admin.php", $id !== '' ? '?id=' . rawurlencode($id) : '', "\">",
			htmlspecialchars($lang['strvaultsharedlogins']), "</a> › ", htmlspecialchars($crumb), "</div>\n";
		$misc->printTitle($lang[$id === '' ? 'strvaultnewsharedtitle' : 'strvaulteditsharedtitle']);

		echo "<form action=\"vault_admin.php\" method=\"post\" class=\"vault-form vault-shared-form\" autocomplete=\"off\">\n";
		echo "<div class=\"vault-field\"><label for=\"vault-server\">", htmlspecialchars($lang['strserver']), "</label>",
			"<select id=\"vault-server\" name=\"server_id\" data-vault-dbs=\"\">\n";
		foreach ($servers as $s) {
			echo "<option value=\"", htmlspecialchars($s['key']), "\" data-list=\"vault-dbs-", htmlspecialchars($s['key']), "\"",
				$s['key'] === $f['server_id'] ? ' selected="selected"' : '', ">", htmlspecialchars($s['name']), "</option>\n";
		}
		echo "</select><span class=\"vault-hint\">", htmlspecialchars($lang['strvaultserverhint']), "</span></div>\n";

		$listId = 'vault-dbs-' . $f['server_id'];
		echo "<div class=\"vault-field\"><label for=\"vault-database\">", htmlspecialchars($lang['strdatabase']), "</label>",
			"<input type=\"text\" id=\"vault-database\" name=\"database\" list=\"", htmlspecialchars($listId), "\" maxlength=\"63\" required=\"required\" value=\"",
			htmlspecialchars($f['database']), "\" /></div>\n";
		foreach ($servers as $s) {
			$dbs = vaultAllowedDatabases($s['key']);
			if (!$dbs && $s['default_db'] !== '') $dbs = array($s['default_db']);
			echo "<datalist id=\"vault-dbs-", htmlspecialchars($s['key']), "\">";
			foreach ($dbs as $db) echo "<option value=\"", htmlspecialchars($db), "\"></option>";
			echo "</datalist>\n";
		}

		echo "<div class=\"vault-field\"><label for=\"vault-label\">", htmlspecialchars($lang['strvaultlabel']), "</label>",
			"<input type=\"text\" id=\"vault-label\" name=\"label\" maxlength=\"100\" required=\"required\" value=\"", htmlspecialchars($f['label']), "\" />",
			"<span class=\"vault-hint\">", htmlspecialchars($lang['strvaultlabelhint']), "</span></div>\n";
		echo "<div class=\"vault-field\"><label for=\"vault-pguser\">", htmlspecialchars($lang['strvaultpgusername']), "</label>",
			"<input type=\"text\" id=\"vault-pguser\" name=\"pg_username\" maxlength=\"63\" required=\"required\" autocomplete=\"off\" class=\"vault-mono\" value=\"",
			htmlspecialchars($f['pg_username']), "\" /></div>\n";
		// Never a value: the stored password is not shown, and a typed one is not echoed back.
		echo "<div class=\"vault-field\"><label for=\"vault-password\">", htmlspecialchars($lang['strpassword']), "</label>",
			"<input type=\"password\" id=\"vault-password\" name=\"password\" autocomplete=\"new-password\" maxlength=\"1000\"",
			$id === '' ? ' required="required"' : '', " placeholder=\"", $id === '' ? '' : htmlspecialchars($lang['strvaultkeeppassword']), "\" />",
			"<span class=\"vault-hint\">", htmlspecialchars($lang['strvaultlockhint']), "</span></div>\n";

		echo "<fieldset class=\"vault-access\"><legend>", htmlspecialchars($lang['strvaultaccesstag']), "</legend>\n";
		foreach (array('read-only' => 'strvaultreadonly', 'read-write' => 'strvaultreadwrite') as $value => $key) {
			echo "<label><input type=\"radio\" name=\"access_label\" value=\"{$value}\"", $f['access_label'] === $value ? ' checked="checked"' : '',
				" /> ", htmlspecialchars(ucfirst($lang[$key])), "</label>\n";
		}
		echo "<span class=\"vault-hint\">", htmlspecialchars($lang['strvaultsharedaccesshint']), "</span></fieldset>\n";

		if ($result !== null) {
			echo "<p class=\"message", $result[1] ? '' : ' error', "\" role=\"status\">", htmlspecialchars($result[0]), "</p>\n";
		}

		if ($id !== '') echo "<input type=\"hidden\" name=\"id\" value=\"", htmlspecialchars($id), "\" />\n";
		echo $misc->form;
		echo "<p><button type=\"submit\" name=\"action\" value=\"save\" class=\"vault-primary\">", htmlspecialchars($lang['strvaulttestandsave']), "</button> ",
			"<button type=\"submit\" name=\"action\" value=\"test\">", htmlspecialchars($lang['strvaulttestonly']), "</button> ",
			"<a href=\"vault_admin.php", $id !== '' ? '?id=' . rawurlencode($id) : '', "\">", htmlspecialchars($lang['strcancel']), "</a></p>\n";
		echo "<p class=\"vault-note\">", htmlspecialchars($lang['strvaultsavetests']), "</p>\n";
		echo "</form>\n";
	}

	/** New or edit: the form, filled from the login (never its password). */
	function doEdit() {
		global $lang, $vault, $vault_id;

		$f = array('server_id' => '', 'database' => '', 'label' => '', 'pg_username' => '', 'access_label' => 'read-only', 'password' => '');
		if ($vault_id !== '') {
			$row = vaultSharedLogin($vault_id);
			if ($row === null) {
				$vault_id = '';
				doDefault($lang['strvaultnotfound'], true);
				return;
			}
			foreach (array('server_id', 'database', 'label', 'pg_username', 'access_label') as $k) $f[$k] = (string) $row[$k];
		}
		vaultSharedForm($vault_id, $f);
	}

	/** Test and save, or only test. */
	function doSaveOrTest($save) {
		global $lang, $vault, $vault_id;

		$f = vaultReadSharedForm();
		$shown = $f;
		$shown['password'] = '';
		if ($vault_id !== '' && vaultSharedLogin($vault_id) === null) {
			$vault_id = '';
			doDefault($lang['strvaultnotfound'], true);
			return;
		}
		try {
			$result = vaultTestShared($vault_id, $f);
			if (!$result['ok']) {
				vaultSharedForm($vault_id, $shown, array($result['reason'], false));
				return;
			}
			if (!$save) {
				vaultSharedForm($vault_id, $shown, array(sprintf($lang['strvaulttestpassed'], $f['database'], $f['pg_username']), true));
				return;
			}
			if ($vault_id === '') {
				$vault_id = $vault->creds->saveShared($vault->identity, $f);
				doDefault(sprintf($lang['strvaultsharedsaved'], $f['label']));
			} else {
				$vault->creds->updateShared($vault->identity, $vault_id, $f);
				doDefault(sprintf($lang['strvaultsharedupdated'], $f['label']));
			}
		} catch (VaultError $e) {
			vaultSharedForm($vault_id, $shown, array(vaultErrorText($e), false));
		} catch (PDOException $e) {
			vaultSharedForm($vault_id, $shown, array(vaultStoreFailed($e), false));
		}
	}

	$misc->printHeader($lang['strvaultsharedlogins'], '<script src="' . htmlspecialchars($misc->asset('js/vault.js')) . '"></script>');
	$misc->printBody();

	// A GET never changes anything; these need a POST, and lib.inc.php has
	// already checked its token.
	if (isset($_POST['cancel'])) $action = '';
	if (!Misc::isPost() && in_array($action, array('share', 'unshare', 'dodelete', 'save', 'test'), true)) $action = '';

	switch ($action) {
		case 'share':
			doShare();
			break;
		case 'unshare':
			doUnshare();
			break;
		case 'delete':
			doDelete();
			break;
		case 'dodelete':
			doDoDelete();
			break;
		case 'audit':
			doAudit();
			break;
		case 'edit':
			doEdit();
			break;
		case 'save':
			doSaveOrTest(true);
			break;
		case 'test':
			doSaveOrTest(false);
			break;
		default:
			doDefault();
			break;
	}

	$misc->printFooter();

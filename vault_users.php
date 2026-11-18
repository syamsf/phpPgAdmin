<?php

	/**
	 * App users, admins only. Local sign-in mode: list, add, reset password,
	 * set groups, disable and enable. Sso mode: everyone the sign-in proxy
	 * has let in (recorded on their first request), with disable and
	 * enable; the provider owns their passwords and groups.
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
	$vault_user = (isset($_REQUEST['user']) && is_scalar($_REQUEST['user'])) ? (string) $_REQUEST['user'] : '';
	$vault_local = $vault->config['auth_mode'] === 'local';

	function vaultMsg($text, $error = false) {
		if ($text === '') return;
		echo "<p class=\"message", ($error ? ' error' : ''), "\" role=\"", ($error ? 'alert' : 'status'), "\">",
			htmlspecialchars($text), "</p>\n";
	}

	function vaultErrorText(VaultError $e) {
		global $lang;
		return isset($lang[$e->getMessage()]) ? $lang[$e->getMessage()] : $e->getMessage();
	}

	function vaultPost($name) {
		return (isset($_POST[$name]) && is_scalar($_POST[$name])) ? (string) $_POST[$name] : '';
	}

	/** The groups typed in a comma-separated field. */
	function vaultSplitGroups($text) {
		return explode(',', $text);
	}

	function vaultIsMe($username) {
		global $vault;
		return $vault->identity !== null && $vault->identity->username === $username;
	}

	/** The users row, or null (after showing the list with a message). */
	function vaultTarget($username) {
		global $vault, $lang;
		$row = $username === '' ? null : $vault->users->get($username);
		if ($row === null) {
			doDefault($lang['strvaultusernotfound'], true);
		}
		return $row;
	}

	function vaultButtons($doLabel) {
		global $lang;
		echo "<p><input type=\"submit\" class=\"vault-primary\" value=\"", htmlspecialchars($doLabel), "\" /> ",
			"<input type=\"submit\" name=\"cancel\" value=\"", htmlspecialchars($lang['strcancel']), "\" formnovalidate=\"formnovalidate\" /></p>\n";
	}

	function vaultHidden($action, $username = null) {
		global $misc;
		echo "<input type=\"hidden\" name=\"action\" value=\"", htmlspecialchars($action), "\" />\n";
		if ($username !== null) {
			echo "<input type=\"hidden\" name=\"user\" value=\"", htmlspecialchars($username), "\" />\n";
		}
		echo $misc->form;
	}

	function doDefault($msg = '', $error = false) {
		global $misc, $lang, $vault, $vault_local;

		$misc->printTrail('root');
		$misc->printTabs('root', 'vaultusers');
		vaultMsg($msg, $error);

		$users = array();
		try {
			$users = $vault->users->all();
		} catch (PDOException $e) {
			error_log('phpPgAdmin: the vault database failed: ' . $e->getMessage());
			vaultMsg($lang['strvaultuserstorefailed'], true);
		}

		$now = time();
		echo "<div class=\"vault-page\">\n";
		echo "<h2>", htmlspecialchars($lang['strvaultusers']), "</h2>\n";
		echo "<p class=\"vault-intro\">", htmlspecialchars($lang[$vault_local ? 'strvaultusersintro' : 'strvaultusersintrosso']), "</p>\n";
		if ($vault_local) {
			echo "<p><a href=\"vault_users.php?action=add\" data-ppa-dialog=\"modal\" class=\"vault-primary\">",
				htmlspecialchars($lang['strvaultadduser']), "</a></p>\n";
		} elseif (!$users) {
			echo "<p>", htmlspecialchars($lang['strvaultnousers']), "</p>\n</div>\n";
			return;
		}
		// Sso mode has no display names or stored groups: the provider owns them.
		$columns = $vault_local
			? array('strvaultusername', 'strvaultdisplayname', 'strvaultgroups', 'strvaultstatus', 'strvaultlastseen', 'stractions')
			: array('strvaultusername', 'strvaultstatus', 'strvaultfirstseen', 'strvaultlastseen', 'stractions');
		echo "<div class=\"vault-table-wrap\">\n<table class=\"vault-table\">\n<thead><tr>";
		foreach ($columns as $key) {
			echo "<th scope=\"col\">", htmlspecialchars($lang[$key]), "</th>";
		}
		echo "</tr></thead>\n<tbody>\n";
		foreach ($users as $row) {
			$u = rawurlencode($row['username']);
			echo "<tr", $row['disabled'] ? ' class="vault-row-failed"' : '', ">\n";
			echo "<td class=\"vault-label\">", htmlspecialchars($row['username']), "</td>\n";
			if ($vault_local) {
				echo "<td>", htmlspecialchars((string) $row['display_name']), "</td>\n";
				echo "<td>";
				if ($row['groups']) {
					foreach ($row['groups'] as $group) {
						echo "<span class=\"vault-chip\">", htmlspecialchars($group), "</span> ";
					}
				} else {
					echo htmlspecialchars($lang['strvaultnogroups']);
				}
				echo "</td>\n";
			}
			echo "<td>", $row['disabled']
				? '<span class="vault-status vault-status-failed">' . htmlspecialchars($lang['strvaultdisabledstatus']) . '</span>'
				: '<span class="vault-status vault-status-ok">' . htmlspecialchars($lang['strvaultactivestatus']) . '</span>', "</td>\n";
			if (!$vault_local) {
				echo "<td>", htmlspecialchars(VaultFormat::date((string) $row['created_at'])), "</td>\n";
			}
			echo "<td>", htmlspecialchars(VaultFormat::ago($row['last_seen_at'], $now)), "</td>\n";
			echo "<td class=\"vault-actions\">";
			if ($vault_local) {
				echo "<a href=\"vault_users.php?action=password&amp;user={$u}\" data-ppa-dialog=\"modal\">", htmlspecialchars($lang['strvaultresetpassword']), "</a> · ",
					"<a href=\"vault_users.php?action=groups&amp;user={$u}\" data-ppa-dialog=\"modal\">", htmlspecialchars($lang['strvaultsetgroups']), "</a> · ";
			}
			if ($row['disabled']) {
				echo "<a href=\"vault_users.php?action=enable&amp;user={$u}\" data-ppa-dialog=\"modal\">", htmlspecialchars($lang['strvaultenable']), "</a>";
			} else {
				echo "<a href=\"vault_users.php?action=disable&amp;user={$u}\" data-ppa-dialog=\"modal\" class=\"vault-delete-link\">", htmlspecialchars($lang['strvaultdisable']), "</a>";
			}
			echo "</td>\n</tr>\n";
		}
		echo "</tbody>\n</table>\n</div>\n</div>\n";
	}

	function doAdd($username = '', $display = '', $groups = '', $error = '') {
		global $misc, $lang;

		$misc->printTrail('root');
		$misc->printTitle($lang['strvaultadduser']);
		vaultMsg($error, true);
		echo "<form action=\"vault_users.php\" method=\"post\" class=\"vault-form\" autocomplete=\"off\">\n";
		echo "<div class=\"vault-field\"><label for=\"vault-username\">", htmlspecialchars($lang['strvaultusername']), "</label>",
			"<input type=\"text\" id=\"vault-username\" name=\"username\" maxlength=\"64\" size=\"30\" required=\"required\" value=\"", htmlspecialchars($username), "\" /></div>\n";
		echo "<div class=\"vault-field\"><label for=\"vault-display\">", htmlspecialchars($lang['strvaultdisplayname']), "</label>",
			"<input type=\"text\" id=\"vault-display\" name=\"display_name\" maxlength=\"128\" size=\"30\" value=\"", htmlspecialchars($display), "\" /></div>\n";
		echo "<div class=\"vault-field\"><label for=\"vault-password\">", htmlspecialchars($lang['strpassword']), "</label>",
			"<input type=\"password\" id=\"vault-password\" name=\"password\" autocomplete=\"new-password\" size=\"30\" required=\"required\" value=\"\" /></div>\n";
		echo "<p class=\"vault-hint\">", htmlspecialchars($lang['strvaultuserpasswordhint']), "</p>\n";
		echo "<div class=\"vault-field\"><label for=\"vault-groups\">", htmlspecialchars($lang['strvaultgroups']), "</label>",
			"<input type=\"text\" id=\"vault-groups\" name=\"groups\" size=\"30\" value=\"", htmlspecialchars($groups), "\" /></div>\n";
		echo "<p class=\"vault-hint\">", htmlspecialchars($lang['strvaultgroupshint']), "</p>\n";
		vaultHidden('saveadd');
		vaultButtons($lang['strvaultadduser']);
		echo "</form>\n";
	}

	function doSaveAdd() {
		global $vault, $lang;

		$username = vaultPost('username');
		$display = vaultPost('display_name');
		$groups = vaultPost('groups');
		try {
			$vault->users->add($username, $display, vaultPost('password'), vaultSplitGroups($groups), $vault->identity->username);
		} catch (VaultError $e) {
			doAdd($username, $display, $groups, vaultErrorText($e));
			return;
		} catch (PDOException $e) {
			error_log('phpPgAdmin: the vault database failed: ' . $e->getMessage());
			doDefault($lang['strvaultuserstorefailed'], true);
			return;
		}
		doDefault(sprintf($lang['strvaultuseradded'], $username));
	}

	function doPassword() {
		global $misc, $lang, $vault_user;

		$row = vaultTarget($vault_user);
		if ($row === null) return;
		$misc->printTrail('root');
		$misc->printTitle($lang['strvaultresetpassword']);
		echo "<form action=\"vault_users.php\" method=\"post\" class=\"vault-form\" autocomplete=\"off\">\n";
		echo "<p class=\"vault-where\"><strong>", htmlspecialchars($row['username']), "</strong></p>\n";
		echo "<div class=\"vault-field\"><label for=\"vault-password\">", htmlspecialchars($lang['strvaultnewpassword']), "</label>",
			"<input type=\"password\" id=\"vault-password\" name=\"password\" autocomplete=\"new-password\" size=\"30\" required=\"required\" value=\"\" /></div>\n";
		echo "<p class=\"vault-hint\">", htmlspecialchars($lang['strvaultuserpasswordhint']), "</p>\n";
		vaultHidden('savepassword', $row['username']);
		vaultButtons($lang['strsave']);
		echo "</form>\n";
	}

	function doSavePassword() {
		global $vault, $vault_user, $lang;

		try {
			$vault->users->resetPassword($vault_user, vaultPost('password'), $vault->identity->username);
		} catch (VaultError $e) {
			doDefault(vaultErrorText($e), true);
			return;
		} catch (PDOException $e) {
			error_log('phpPgAdmin: the vault database failed: ' . $e->getMessage());
			doDefault($lang['strvaultuserstorefailed'], true);
			return;
		}
		doDefault(sprintf($lang['strvaultpasswordreset'], $vault_user));
	}

	function doGroups() {
		global $misc, $lang, $vault, $vault_user;

		$row = vaultTarget($vault_user);
		if ($row === null) return;
		$misc->printTrail('root');
		$misc->printTitle($lang['strvaultsetgroups']);
		echo "<form action=\"vault_users.php\" method=\"post\" class=\"vault-form\">\n";
		echo "<p class=\"vault-where\"><strong>", htmlspecialchars($row['username']), "</strong></p>\n";
		echo "<div class=\"vault-field\"><label for=\"vault-groups\">", htmlspecialchars($lang['strvaultgroups']), "</label>",
			"<input type=\"text\" id=\"vault-groups\" name=\"groups\" size=\"40\" value=\"",
			htmlspecialchars(implode(', ', $vault->users->groupsOf($row['username']))), "\" /></div>\n";
		echo "<p class=\"vault-hint\">", htmlspecialchars($lang['strvaultgroupshint']), "</p>\n";
		vaultHidden('savegroups', $row['username']);
		vaultButtons($lang['strsave']);
		echo "</form>\n";
	}

	function doSaveGroups() {
		global $vault, $vault_user, $lang;

		try {
			$groups = VaultUsers::cleanGroups(vaultSplitGroups(vaultPost('groups')));
			if (vaultIsMe($vault_user) && !in_array($vault->config['admin_group'], $groups, true)) {
				throw new VaultError('strvaultnotyourself');
			}
			$vault->users->setGroups($vault_user, $groups, $vault->identity->username);
		} catch (VaultError $e) {
			doDefault(vaultErrorText($e), true);
			return;
		} catch (PDOException $e) {
			error_log('phpPgAdmin: the vault database failed: ' . $e->getMessage());
			doDefault($lang['strvaultuserstorefailed'], true);
			return;
		}
		doDefault(sprintf($lang['strvaultgroupsset'], $vault_user));
	}

	/** The confirmation for disable (when $disable) or enable. */
	function doConfirmState($disable) {
		global $misc, $lang, $vault_user;

		$row = vaultTarget($vault_user);
		if ($row === null) return;
		if ($disable && vaultIsMe($row['username'])) {
			doDefault($lang['strvaultnotyourself'], true);
			return;
		}
		$misc->printTrail('root');
		$misc->printTitle($lang[$disable ? 'strvaultdisable' : 'strvaultenable']);
		echo "<form action=\"vault_users.php\" method=\"post\" class=\"vault-form\">\n";
		echo "<p>", htmlspecialchars(sprintf($lang[$disable ? 'strvaultconfdisable' : 'strvaultconfenable'], $row['username'])), "</p>\n";
		vaultHidden($disable ? 'dodisable' : 'doenable', $row['username']);
		vaultButtons($lang[$disable ? 'strvaultdisable' : 'strvaultenable']);
		echo "</form>\n";
	}

	function doSetState($disable) {
		global $vault, $vault_user, $lang;

		try {
			if ($disable && vaultIsMe($vault_user)) {
				throw new VaultError('strvaultnotyourself');
			}
			$vault->users->setDisabled($vault_user, $disable, $vault->identity->username);
		} catch (VaultError $e) {
			doDefault(vaultErrorText($e), true);
			return;
		} catch (PDOException $e) {
			error_log('phpPgAdmin: the vault database failed: ' . $e->getMessage());
			doDefault($lang['strvaultuserstorefailed'], true);
			return;
		}
		doDefault(sprintf($lang[$disable ? 'strvaultuserdisabled' : 'strvaultuserenabled'], $vault_user));
	}

	$misc->printHeader($lang['strvaultusers']);
	$misc->printBody();

	// Sso mode: the provider owns accounts, passwords and groups.
	if (!$vault_local && in_array($action, array('add', 'saveadd', 'password', 'savepassword', 'groups', 'savegroups'), true)) {
		http_response_code(404);
		doDefault($lang['strvaultuserssso'], true);
		$misc->printFooter();
		exit;
	}

	if (isset($_POST['cancel'])) $action = '';
	if (!Misc::isPost() && in_array($action, array('saveadd', 'savepassword', 'savegroups', 'dodisable', 'doenable'), true)) $action = '';

	switch ($action) {
		case 'add': doAdd(); break;
		case 'saveadd': doSaveAdd(); break;
		case 'password': doPassword(); break;
		case 'savepassword': doSavePassword(); break;
		case 'groups': doGroups(); break;
		case 'savegroups': doSaveGroups(); break;
		case 'disable': doConfirmState(true); break;
		case 'dodisable': doSetState(true); break;
		case 'enable': doConfirmState(false); break;
		case 'doenable': doSetState(false); break;
		default: doDefault(); break;
	}

	$misc->printFooter();

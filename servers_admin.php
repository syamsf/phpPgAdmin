<?php

	/**
	 * Manage servers (boards 6 and 7), admins only: the env and UI servers
	 * with their login counts, add / edit / enable / disable a UI server,
	 * test a connection with a throwaway login, and delete a server (or an
	 * env server removed from the env) with its logins. Env servers are
	 * read-only here.
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
	$vault_key = (isset($_REQUEST['key']) && is_scalar($_REQUEST['key'])) ? (string) $_REQUEST['key'] : '';
	$vault_ui_allowed = !empty($vault->config['servers_allow_ui']);

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

	function vaultStoreFailed(PDOException $e) {
		global $lang;
		error_log('phpPgAdmin: the vault database failed: ' . $e->getMessage());
		return $lang['strvaultstorefailed'];
	}

	/** After a change the tree has to show the new server list. */
	function vaultReloadTree() {
		echo "<script>if (window.ppa && window.ppa.reloadTree) window.ppa.reloadTree();</script>\n";
	}

	function vaultButtons($doLabel, $id = '', $disabled = false) {
		global $lang;
		echo "<p><input type=\"submit\"", $id !== '' ? " id=\"{$id}\"" : '', " class=\"vault-primary\" value=\"", htmlspecialchars($doLabel), "\"",
			$disabled ? ' disabled="disabled"' : '', " /> ",
			"<input type=\"submit\" name=\"cancel\" value=\"", htmlspecialchars($lang['strcancel']), "\" formnovalidate=\"formnovalidate\" /></p>\n";
	}

	/** One server's row, or null. */
	function vaultServer($key) {
		global $vault;
		return $key === '' ? null : $vault->servers->get($key);
	}

	/** "host:port" of a row. */
	function vaultHostPort($row) {
		return $row['host'] . ':' . $row['port'];
	}

	function vaultLockIcon() {
		return '<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false"><rect x="5" y="11" width="14" height="10" rx="2"></rect><path d="M8 11V7a4 4 0 0 1 8 0v4"></path></svg>';
	}

	function vaultLoginsText($row) {
		global $lang;
		$personal = (int) $row['personal_count'];
		$shared = (int) $row['shared_count'];
		if ($personal + $shared === 0) return $lang['strvaultnologins'];
		if ($row['status'] === 'removed') return sprintf($lang['strvaultsavedhidden'], $personal + $shared);
		return sprintf($lang['strvaultsavedshared'], $personal, $shared);
	}

	/** A POST form with one button that looks like a link (enable / disable). */
	function vaultStateForm($action, $key, $label, $class = '') {
		global $misc;
		return "<form action=\"servers_admin.php\" method=\"post\" class=\"vault-inline\">"
			. "<input type=\"hidden\" name=\"action\" value=\"" . $action . "\" />"
			. "<input type=\"hidden\" name=\"key\" value=\"" . htmlspecialchars($key) . "\" />"
			. $misc->form
			. "<button type=\"submit\" class=\"vault-linkbtn" . ($class !== '' ? ' ' . $class : '') . "\">" . htmlspecialchars($label) . "</button></form>";
	}

	function doDefault($msg = '', $error = false) {
		global $misc, $lang, $vault, $vault_ui_allowed;

		$misc->printTrail('root');
		$misc->printTabs('root', 'serversadmin');
		vaultMsg($msg, $error);

		$rows = array();
		try {
			$rows = $vault->servers->listWithCounts();
		} catch (PDOException $e) {
			vaultMsg(vaultStoreFailed($e), true);
		}

		echo "<div class=\"vault-page vault-admin\">\n";
		echo "<div class=\"vault-admin-head\">\n<div>\n";
		echo "<h2>", htmlspecialchars($lang['strvaultserversadmin']), "</h2>\n";
		echo "<p class=\"vault-intro\">", htmlspecialchars($lang['strvaultserversintro']), "</p>\n";
		echo "</div>\n";
		if ($vault_ui_allowed) {
			echo "<a href=\"servers_admin.php?action=add\" class=\"vault-button\">", htmlspecialchars($lang['strvaultaddserver']), "</a>\n";
		}
		echo "</div>\n";

		echo "<div class=\"vault-table-wrap\">\n<table class=\"vault-table\">\n<thead><tr>";
		foreach (array('strserver', 'strvaultsource', 'strhost', 'strvaultssl', 'strvaultlogins', 'strvaultstatus', 'stractions') as $key) {
			echo "<th scope=\"col\">", htmlspecialchars(isset($lang[$key]) ? $lang[$key] : $key), "</th>";
		}
		echo "</tr></thead>\n<tbody>\n";
		foreach ($rows as $row) {
			$k = rawurlencode($row['key']);
			$isEnv = $row['source'] === 'env';
			if ($row['status'] === 'removed') {
				$status = '<span class="vault-status vault-status-failed">' . htmlspecialchars($lang['strvaultremovedfromenv']) . '</span>';
			} elseif ($row['status'] === 'disabled') {
				$status = '<span class="vault-status vault-status-off">' . htmlspecialchars($lang['strvaultserverstatusoff']) . '</span>';
			} else {
				$status = '<span class="vault-status vault-status-ok">' . htmlspecialchars($lang['strvaultactive']) . '</span>';
			}
			echo "<tr", $row['status'] === 'active' ? '' : ' class="vault-row-off"', ">\n";
			echo "<td class=\"vault-label\">", htmlspecialchars($row['name']), "</td>\n";
			echo "<td>";
			if ($isEnv) {
				echo "<span class=\"vault-lock\" title=\"", htmlspecialchars($lang['strvaultserverlock']), "\">", vaultLockIcon(), ' ',
					htmlspecialchars($lang['strvaultsourceenv']), "</span>";
			} else {
				echo htmlspecialchars($lang['strvaultsourceui']);
			}
			echo "</td>\n";
			echo "<td class=\"vault-mono\">", htmlspecialchars(vaultHostPort($row));
			if (!empty($row['pgbouncer'])) {
				echo " <span class=\"vault-muted\" title=\"", htmlspecialchars($lang['strvaultpgbouncerhint']), "\">",
					htmlspecialchars($lang['strvaultpgbouncertag']), "</span>";
			}
			echo "</td>\n";
			echo "<td>", htmlspecialchars($row['sslmode']), "</td>\n";
			echo "<td>", htmlspecialchars(vaultLoginsText($row)), "</td>\n";
			echo "<td>", $status, "</td>\n";
			echo "<td class=\"vault-actions\">";
			if ($isEnv && $row['status'] === 'removed') {
				echo "<a href=\"servers_admin.php?action=delete&amp;key={$k}\" data-ppa-dialog=\"modal\" class=\"vault-delete-link\">",
					htmlspecialchars($lang['strvaultdeleteitslogins']), "</a>";
			} elseif ($isEnv) {
				echo "<span class=\"vault-muted\">", htmlspecialchars($lang['strvaultserveredinenv']), "</span>";
			} else {
				$parts = array();
				if ($vault_ui_allowed) {
					$parts[] = "<a href=\"servers_admin.php?action=edit&amp;key={$k}\">" . htmlspecialchars($lang['strvaultserveredit']) . "</a>";
					$parts[] = $row['status'] === 'active'
						? vaultStateForm('disable', $row['key'], $lang['strvaultdisable'])
						: vaultStateForm('enable', $row['key'], $lang['strvaultenable']);
				}
				$parts[] = "<a href=\"servers_admin.php?action=delete&amp;key={$k}\" data-ppa-dialog=\"modal\" class=\"vault-delete-link\">"
					. htmlspecialchars($lang['strdelete']) . "</a>";
				echo implode(' · ', $parts);
			}
			echo "</td>\n</tr>\n";
		}
		echo "</tbody>\n</table>\n</div>\n";
		echo "<p class=\"vault-note\">", htmlspecialchars($lang['strvaultserverenvnote']), "</p>\n";
		echo "</div>\n";
	}

	/** "group dba, user dan" for the principals a server's shared logins go to. */
	function vaultPrincipalsText(array $principals) {
		global $lang;
		$out = array();
		foreach ($principals as $p) {
			$out[] = $lang[$p[0] === 'group' ? 'strvaultsharegroup' : 'strvaultshareuser'] . ' ' . $p[1];
		}
		return implode(', ', $out);
	}

	/** The delete dialog: what goes with the server, and the key to type. */
	function doDelete($error = '') {
		global $misc, $lang, $vault, $vault_key;

		$row = vaultServer($vault_key);
		if ($row === null) {
			doDefault($lang['strvaultservernotfound'], true);
			return;
		}
		if ($row['source'] === 'env' && $row['status'] !== 'removed') {
			doDefault($lang['strvaultenvreadonly'], true);
			return;
		}
		$impact = array('personal' => 0, 'owners' => 0, 'shared' => 0, 'principals' => array());
		try {
			$impact = $vault->servers->impact($row['key']);
		} catch (PDOException $e) {
			doDefault(vaultStoreFailed($e), true);
			return;
		}
		$total = $impact['personal'] + $impact['shared'];

		$misc->printTrail('root');
		$misc->printTitle(sprintf($lang['strvaultdeleteserver'], $row['name']));
		vaultMsg($error, true);
		echo "<form action=\"servers_admin.php\" method=\"post\" class=\"vault-form\" autocomplete=\"off\">\n";
		echo "<p>", htmlspecialchars($lang['strvaultdeleteserveralso']), "</p>\n<ul class=\"vault-impact\">\n";
		if ($impact['personal'] > 0) {
			echo "<li><strong>", htmlspecialchars($impact['personal'] === 1 ? $lang['strvaultonesavedlogin']
				: sprintf($lang['strvaultnsavedlogins'], $impact['personal'], $impact['owners'])), "</strong></li>\n";
		}
		if ($impact['shared'] > 0) {
			echo "<li><strong>", htmlspecialchars($impact['shared'] === 1 ? $lang['strvaultoneshared']
				: sprintf($lang['strvaultnsharedloginsdel'], $impact['shared'])), "</strong>";
			if ($impact['principals']) {
				echo htmlspecialchars(sprintf($lang['strvaultsharedwithlist'], vaultPrincipalsText($impact['principals'])));
			}
			echo "</li>\n";
		}
		if ($total === 0) {
			echo "<li>", htmlspecialchars($lang['strvaultnologins']), "</li>\n";
		}
		echo "</ul>\n";
		echo "<p>", htmlspecialchars($lang['strvaultdeleteserverwarn']), "</p>\n";
		echo "<div class=\"vault-field\"><label for=\"vault-confirm-key\">", htmlspecialchars($lang['strvaultconfirmkey']), "</label>",
			"<input type=\"text\" id=\"vault-confirm-key\" name=\"confirm\" class=\"vault-mono\" maxlength=\"63\" required=\"required\" ",
			"autocomplete=\"off\" autocapitalize=\"off\" spellcheck=\"false\" data-key=\"", htmlspecialchars($row['key']), "\" value=\"\" /></div>\n";
		echo "<input type=\"hidden\" name=\"action\" value=\"dodelete\" />\n";
		echo "<input type=\"hidden\" name=\"key\" value=\"", htmlspecialchars($row['key']), "\" />\n";
		echo $misc->form;
		$label = $total === 0 ? $lang['strvaultdeleteserverbtn0']
			: ($total === 1 ? $lang['strvaultdeleteserverbtn1'] : sprintf($lang['strvaultdeleteserverbtn'], $total));
		vaultButtons($label, 'vault-confirm-go');
		echo "<p class=\"vault-hint\">", htmlspecialchars($lang['strvaultconfirmhint']), "</p>\n";
		echo "</form>\n";
		// Runs each time the dialog is shown. The server checks the key again.
		echo "<script>(function () {\n",
			"\tvar i = document.getElementById('vault-confirm-key'), b = document.getElementById('vault-confirm-go');\n",
			"\tif (!i || !b) return;\n",
			"\tfunction sync() { b.disabled = i.value !== i.getAttribute('data-key'); }\n",
			"\ti.addEventListener('input', sync);\n\tsync();\n})();</script>\n";
	}

	function doDoDelete() {
		global $vault, $vault_key, $lang;

		$row = vaultServer($vault_key);
		if ($row === null) {
			doDefault($lang['strvaultservernotfound'], true);
			return;
		}
		if (vaultPost('confirm') !== $row['key']) {
			doDelete($lang['strvaultwrongkey']);
			return;
		}
		try {
			$counts = $vault->servers->delete($row['key'], $vault->identity->username);
		} catch (VaultError $e) {
			doDefault(vaultErrorText($e), true);
			return;
		} catch (PDOException $e) {
			doDefault(vaultStoreFailed($e), true);
			return;
		}
		doDefault(sprintf($lang['strvaultserverdeleted'], $row['name'], $counts['personal'] + $counts['shared']));
		vaultReloadTree();
	}

	/** Enable or disable a UI server (POST only). */
	function doSetState($enable) {
		global $vault, $vault_key, $lang;

		$row = vaultServer($vault_key);
		if ($row === null) {
			doDefault($lang['strvaultservernotfound'], true);
			return;
		}
		try {
			$vault->servers->setStatus($row['key'], $enable ? 'active' : 'disabled', $vault->identity->username);
		} catch (VaultError $e) {
			doDefault(vaultErrorText($e), true);
			return;
		} catch (PDOException $e) {
			doDefault(vaultStoreFailed($e), true);
			return;
		}
		doDefault(sprintf($lang[$enable ? 'strvaultserverenabled' : 'strvaultserverdisabledmsg'], $row['name']));
		vaultReloadTree();
	}

	/**
	 * The add / edit form. $f holds what to show; $edit is the key being
	 * edited or '' for a new server; $result is the test's line: array(text, ok).
	 */
	function vaultServerForm($edit, array $f, $result = null, $testUser = '') {
		global $misc, $lang;

		$misc->printTrail('root');
		echo "<div class=\"vault-crumb\"><a href=\"servers_admin.php\">", htmlspecialchars($lang['strvaultserversadmin']), "</a> › ",
			htmlspecialchars($lang[$edit === '' ? 'strvaultaddservertitle' : 'strvaulteditservertitle']), "</div>\n";
		$misc->printTitle($lang[$edit === '' ? 'strvaultaddservertitle' : 'strvaulteditservertitle']);
		echo "<p class=\"vault-intro\">", htmlspecialchars($lang['strvaultaddserverintro']), "</p>\n";

		echo "<form action=\"servers_admin.php\" method=\"post\" class=\"vault-form\" autocomplete=\"off\">\n";
		echo "<div class=\"vault-field\"><label for=\"vault-skey\">", htmlspecialchars($lang['strvaultkey']), "</label>",
			"<input type=\"text\" id=\"vault-skey\" name=\"newkey\" class=\"vault-mono\" maxlength=\"63\" required=\"required\" ",
			"pattern=\"[a-z0-9][a-z0-9\\-]*\" value=\"", htmlspecialchars($f['key']), "\"", $edit !== '' ? ' readonly="readonly"' : '', " />",
			"<span class=\"vault-hint\">", htmlspecialchars($lang['strvaultkeyhint']), "</span></div>\n";
		echo "<div class=\"vault-field\"><label for=\"vault-sname\">", htmlspecialchars($lang['strvaultdisplayname']), "</label>",
			"<input type=\"text\" id=\"vault-sname\" name=\"name\" maxlength=\"100\" required=\"required\" value=\"", htmlspecialchars($f['name']), "\" /></div>\n";
		echo "<div class=\"vault-field\"><label for=\"vault-shost\">", htmlspecialchars($lang['strhost']), "</label>",
			"<input type=\"text\" id=\"vault-shost\" name=\"host\" maxlength=\"253\" required=\"required\" value=\"", htmlspecialchars($f['host']), "\" />",
			"<span class=\"vault-hint\">", htmlspecialchars($lang['strvaulthosthint']), "</span></div>\n";
		echo "<div class=\"vault-field\"><label for=\"vault-sport\">", htmlspecialchars($lang['strport']), "</label>",
			"<input type=\"number\" id=\"vault-sport\" name=\"port\" min=\"1\" max=\"65535\" required=\"required\" value=\"", htmlspecialchars($f['port']), "\" /></div>\n";
		echo "<div class=\"vault-field\"><label for=\"vault-sssl\">", htmlspecialchars($lang['strvaultsslmode']), "</label>",
			"<select id=\"vault-sssl\" name=\"sslmode\">\n";
		foreach (VaultServers::SSLMODES as $mode) {
			echo "<option value=\"{$mode}\"", $f['sslmode'] === $mode ? ' selected="selected"' : '', ">{$mode}</option>\n";
		}
		echo "</select></div>\n";
		echo "<div class=\"vault-field\"><label for=\"vault-sdb\">", htmlspecialchars($lang['strvaultdefaultdb']), "</label>",
			"<input type=\"text\" id=\"vault-sdb\" name=\"default_db\" maxlength=\"63\" required=\"required\" value=\"", htmlspecialchars($f['default_db']), "\" />",
			"<span class=\"vault-hint\">", htmlspecialchars($lang['strvaultdefaultdbhint']), "</span></div>\n";
		echo "<div class=\"vault-field\"><label><input type=\"checkbox\" name=\"pgbouncer\" value=\"1\"", $f['pgbouncer'] ? ' checked="checked"' : '', " /> ",
			htmlspecialchars($lang['strvaultpgbouncer']), "</label><span class=\"vault-hint\">", htmlspecialchars($lang['strvaultpgbouncerhint']), "</span></div>\n";
		echo "<div class=\"vault-field\"><label><input type=\"checkbox\" name=\"enabled\" value=\"1\"", $f['enabled'] ? ' checked="checked"' : '', " /> ",
			htmlspecialchars($lang['strenabled']), "</label><span class=\"vault-hint\">", htmlspecialchars($lang['strvaultenabledhint']), "</span></div>\n";

		echo "<fieldset class=\"vault-test\"><legend>", htmlspecialchars($lang['strvaulttestconn']), "</legend>\n";
		echo "<p class=\"vault-hint\">", htmlspecialchars($lang['strvaulttestconnhint']), "</p>\n";
		echo "<div class=\"vault-field\"><label for=\"vault-tuser\">", htmlspecialchars($lang['strusername']), "</label>",
			"<input type=\"text\" id=\"vault-tuser\" name=\"test_user\" maxlength=\"63\" autocomplete=\"off\" class=\"vault-mono\" value=\"", htmlspecialchars($testUser), "\" /></div>\n";
		// Never a value: a typed password is not echoed back.
		echo "<div class=\"vault-field\"><label for=\"vault-tpass\">", htmlspecialchars($lang['strpassword']), "</label>",
			"<input type=\"password\" id=\"vault-tpass\" name=\"test_password\" autocomplete=\"new-password\" maxlength=\"1000\" value=\"\" /></div>\n";
		echo "<p><button type=\"submit\" name=\"action\" value=\"test\" formnovalidate=\"formnovalidate\">", htmlspecialchars($lang['strvaulttestconnbtn']), "</button></p>\n";
		if ($result !== null) {
			echo "<p class=\"message", $result[1] ? '' : ' error', "\" role=\"status\">", htmlspecialchars($result[0]), "</p>\n";
		}
		echo "</fieldset>\n";

		if ($edit !== '') echo "<input type=\"hidden\" name=\"key\" value=\"", htmlspecialchars($edit), "\" />\n";
		echo $misc->form;
		echo "<p><button type=\"submit\" name=\"action\" value=\"save\" class=\"vault-primary\">", htmlspecialchars($lang['strvaultsaveserver']), "</button> ",
			"<a href=\"servers_admin.php\">", htmlspecialchars($lang['strcancel']), "</a></p>\n";
		echo "</form>\n";
	}

	/** The row's fields as the form shows them. */
	function vaultFormFrom($row) {
		return array('key' => $row['key'], 'name' => $row['name'], 'host' => $row['host'], 'port' => (string) $row['port'],
			'sslmode' => $row['sslmode'] === '' ? 'prefer' : $row['sslmode'], 'default_db' => $row['default_db'],
			'pgbouncer' => !empty($row['pgbouncer']), 'enabled' => $row['status'] === 'active');
	}

	/** What the form posted. */
	function vaultReadServerForm($edit) {
		return array(
			'key' => $edit !== '' ? $edit : trim(vaultPost('newkey')),
			'name' => trim(vaultPost('name')),
			'host' => trim(vaultPost('host')),
			'port' => trim(vaultPost('port')),
			'sslmode' => vaultPost('sslmode'),
			'default_db' => trim(vaultPost('default_db')),
			'pgbouncer' => vaultPost('pgbouncer') !== '',
			'enabled' => vaultPost('enabled') !== '',
		);
	}

	function doAddForm() {
		vaultServerForm('', array('key' => '', 'name' => '', 'host' => '', 'port' => '5432', 'sslmode' => 'require',
			'default_db' => 'postgres', 'pgbouncer' => false, 'enabled' => true));
	}

	function doEditForm() {
		global $lang, $vault_key;

		$row = vaultServer($vault_key);
		if ($row === null) {
			doDefault($lang['strvaultservernotfound'], true);
		} elseif ($row['source'] !== 'ui') {
			doDefault($lang['strvaultenvreadonly'], true);
		} else {
			vaultServerForm($row['key'], vaultFormFrom($row));
		}
	}

	/** Save (add, or change when a key is being edited). */
	function doSave() {
		global $lang, $vault, $vault_key;

		$edit = $vault_key;
		$f = vaultReadServerForm($edit);
		try {
			if ($edit !== '') {
				$vault->servers->update($edit, $f, $vault->identity->username);
			} else {
				$vault->servers->add($f, $vault->identity->username);
			}
		} catch (VaultError $e) {
			vaultServerForm($edit, $f, array(vaultErrorText($e), false), vaultPost('test_user'));
			return;
		} catch (PDOException $e) {
			vaultServerForm($edit, $f, array(vaultStoreFailed($e), false), vaultPost('test_user'));
			return;
		}
		doDefault(sprintf($lang[$edit !== '' ? 'strvaultserversaved' : 'strvaultserveradded'], $f['name']));
		vaultReloadTree();
	}

	/** Connect with the typed login, keep nothing. */
	function doTest() {
		global $lang, $vault, $vault_key;

		$edit = $vault_key;
		$f = vaultReadServerForm($edit);
		$user = trim(vaultPost('test_user'));
		$password = vaultPost('test_password');
		try {
			if ($edit !== '') {
				$row = vaultServer($edit);
				if ($row === null) throw new VaultError('strvaultservernotfound');
				if ($row['source'] !== 'ui') throw new VaultError('strvaultenvreadonly');
			}
			$f = array_merge($f, $vault->servers->clean($f));
			if ($user === '' || strlen($user) > 63 || $password === '') {
				throw new VaultError('strvaulttestneedlogin');
			}
			$result = VaultConnect::test(array('host' => $f['host'], 'port' => $f['port'], 'sslmode' => $f['sslmode']),
				$f['default_db'], $user, $password, Vault::appName($vault->identity->username));
		} catch (VaultError $e) {
			$f['port'] = (string) $f['port'];
			vaultServerForm($edit, $f, array(vaultErrorText($e), false), $user);
			return;
		}
		$f['port'] = (string) $f['port'];
		if ($result['ok']) {
			$ssl = in_array($f['sslmode'], array('require', 'verify-full'), true) ? $lang['strvaultservertestssl'] : '';
			$line = array(sprintf($lang['strvaultservertestok'], $f['host'], $f['port'], $ssl, $result['version']), true);
		} else {
			$line = array($result['reason'], false);
		}
		vaultServerForm($edit, $f, $line, $user);
	}

	// Adding, changing and testing need SERVERS_ALLOW_UI; deleting does not.
	if (!$vault_ui_allowed && in_array($action, array('add', 'edit', 'save', 'test', 'enable', 'disable'), true)) {
		http_response_code(403);
		$misc->printHeader($lang['strvaultserversadmin']);
		$misc->printBody();
		$misc->printTrail('root');
		$misc->printTabs('root', 'serversadmin');
		vaultMsg($lang['strvaultserveruidisabled'], true);
		$misc->printFooter();
		exit;
	}

	$misc->printHeader($lang['strvaultserversadmin']);
	$misc->printBody();

	// A GET never changes anything; these need a POST, and lib.inc.php has
	// already checked its token.
	if (isset($_POST['cancel'])) $action = '';
	if (!Misc::isPost() && in_array($action, array('save', 'test', 'dodelete', 'enable', 'disable'), true)) $action = '';

	switch ($action) {
		case 'add': doAddForm(); break;
		case 'edit': doEditForm(); break;
		case 'save': doSave(); break;
		case 'test': doTest(); break;
		case 'delete': doDelete(); break;
		case 'dodelete': doDoDelete(); break;
		case 'enable': doSetState(true); break;
		case 'disable': doSetState(false); break;
		default: doDefault(); break;
	}

	$misc->printFooter();

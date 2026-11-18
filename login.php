<?php

	/**
	 * Login screen
	 *
	 * $Id: login.php,v 1.38 2007/09/04 19:39:48 ioguix Exp $
	 */
	global $conf, $plugin_manager;

	// This needs to be an include once to prevent lib.inc.php infinite recursive includes.
	// Check to see if the configuration file exists, if not, explain
	require_once('./libraries/lib.inc.php');

	if (!isset($plugin_manager))
		$plugin_manager = new PluginManager($_SESSION['webdbLanguage']);

	$misc->printHeader($lang['strlogin'], '<script src="' . htmlspecialchars($misc->asset('js/vault.js')) . '"></script>');
	$misc->printBody();
	$misc->printTrail('root');
	$misc->printTabs('root', 'servers');

	$server = (isset($_REQUEST['server']) && is_scalar($_REQUEST['server'])) ? (string) $_REQUEST['server'] : '';

	$server_info = $misc->getServerInfo($server);

	$login_vault = (isset($GLOBALS['vault']) && $GLOBALS['vault'] instanceof Vault && $GLOBALS['vault']->identity !== null)
		? $GLOBALS['vault'] : null;
	list($login_key, $login_db) = Misc::vaultScope($server_info ?? array());

	// Per-database logins name the database; whole-server ones the server.
	if (isset($server_info['database'])) {
		$login_title = sprintf($lang['strvaultlogintitle'], $server_info['database']);
		$login_sub = sprintf($lang['strvaultloginperdb'], $server_info['server_desc'] ?? '');
		$login_where = array($server_info['server_desc'] ?? '', $server_info['database']);
	} else {
		$login_title = sprintf($lang['strvaultlogintitle'], $server_info['desc'] ?? '');
		$login_host = empty($server_info['host']) ? 'localhost' : $server_info['host'];
		$login_sub = sprintf($lang['strvaultloginserver'], $login_host . ':' . ($server_info['port'] ?? ''));
		$login_where = array($server_info['desc'] ?? '', $login_db);
	}

	echo "<div class=\"vault-login-head\">\n";
	echo "<h2>", htmlspecialchars($login_title), "</h2>\n";
	echo "<p class=\"vault-login-sub\">", htmlspecialchars($login_sub), "</p>\n";
	echo "</div>\n";

	// A message for the next page, e.g. a refused saved login (lib.inc.php).
	$login_flash = isset($_SESSION['ppa_flash']) && is_string($_SESSION['ppa_flash']) ? $_SESSION['ppa_flash'] : '';
	unset($_SESSION['ppa_flash']);

	// Set by ppa_vault_login_failed(): a saved login's password was refused.
	$login_failed = isset($GLOBALS['loginVaultFailed']) && is_array($GLOBALS['loginVaultFailed'])
		? $GLOBALS['loginVaultFailed'] : null;

	if (isset($msg)) {
		if ($login_failed !== null) {
			echo "<div class=\"message error login-error\" role=\"alert\"><p><strong>", htmlspecialchars($msg), "</strong> ";
			echo htmlspecialchars(sprintf($lang['strvaultnolongerworks'], $login_failed['label']));
			if ($login_failed['kind'] === 'personal') {
				echo " <a href=\"", htmlspecialchars('vault.php?action=password&id=' . rawurlencode($login_failed['id'])), "\">",
					htmlspecialchars($lang['strvaultupdatepassword']), "</a>";
			} else {
				echo " ", htmlspecialchars($lang['strvaultaskadmin']);
			}
			echo "</p>\n</div>\n";
		} elseif (!empty($loginErrorReason)) {
			// A failed connection: say why in plain words. The server's own
			// message (host, port, addresses) goes to the log, not the page.
			echo "<div class=\"message error login-error\" role=\"alert\"><p><strong>", htmlspecialchars($msg), "</strong>";
			echo " ", htmlspecialchars($loginErrorReason), "</p>\n";
			echo "</div>\n";
		} elseif ($msg === $lang['strvaultloginrevoked'] || $msg === $lang['strvaultlogindecrypt']) {
			echo "<p class=\"message error\" role=\"alert\">", htmlspecialchars($msg), "</p>\n";
		} else {
			$misc->printMsg($msg);
		}
	}
	if ($login_flash !== '') {
		echo "<p class=\"message error\" role=\"alert\">", htmlspecialchars($login_flash), "</p>\n";
	}

	$md5_server = md5($server);

	// The username to show: the one just tried, if this is a failed login.
	$login_username = '';
	if (isset($_POST['loginUsername']) && is_scalar($_POST['loginUsername']))
		$login_username = (string) $_POST['loginUsername'];
	elseif (isset($loginUsername) && is_scalar($loginUsername))
		$login_username = (string) $loginUsername;

	// Post the login to the page that asked for it, so that page is shown
	// once logged in (lib.inc.php redirects to it, with only the fields of
	// LOGIN_PASSTHROUGH: where to go, never what to do). Pages that only
	// make sense with a posted form or as a download go through redirect.php.
	$login_action = basename($_SERVER['SCRIPT_NAME'] ?? '');
	if (!preg_match('/^[a-z_]+\.php$/', $login_action)
		|| in_array($login_action, array('login.php', 'logout.php', 'redirect.php', 'index.php', 'sql.php',
			'dataexport.php', 'dbexport.php', 'dataimport.php', 'ajax-ac-insert.php', 'browser.php'), true))
		$login_action = 'redirect.php';

	// The fields both forms carry: where the user was going (never an
	// action: a link that says action=drop must not drop anything once they
	// log in), the form token and the server.
	if (!empty($_POST)) $vars =& $_POST;
	else $vars =& $_GET;
	$login_hidden = '';
	foreach (Misc::LOGIN_PASSTHROUGH as $key) {
		if (!isset($vars[$key]) || !is_scalar($vars[$key])) continue;
		$login_hidden .= "<input type=\"hidden\" name=\"" . htmlspecialchars($key) . "\" value=\"" . htmlspecialchars((string) $vars[$key]) . "\" />\n";
	}
	$login_hidden .= "<input type=\"hidden\" name=\"ppa_csrf\" value=\"" . htmlspecialchars($misc->csrfToken()) . "\" />\n";
	$login_hidden .= "<input type=\"hidden\" name=\"loginServer\" value=\"" . htmlspecialchars($server) . "\" />\n";

	// The saved logins this person may use here: their own, then shared ones.
	$login_saved = array();
	if ($login_vault !== null && $login_key !== '') {
		try {
			$login_saved = $login_vault->creds->listFor($login_vault->identity, $login_key, $login_db, VaultStore::now());
		} catch (PDOException $e) {
			error_log('phpPgAdmin: the vault database failed: ' . $e->getMessage());
		}
	}

	if ($login_saved) {
		$login_now = time();
		$login_groups = array('personal' => array(), 'shared' => array());
		foreach ($login_saved as $row) {
			$login_groups[$row['kind'] === 'personal' ? 'personal' : 'shared'][] = $row;
		}
		$login_access = array('read-only' => $lang['strvaultreadonly'], 'read-write' => $lang['strvaultreadwrite']);
?>
<section class="vault-login-section" aria-labelledby="vault-saved-h">
<h3 id="vault-saved-h"><?php echo htmlspecialchars($lang['strvaultusesaved']); ?></h3>
<form id="login_saved_form" action="<?php echo htmlspecialchars($login_action); ?>" method="post">
<?php echo $login_hidden; ?>
	<div class="vault-field">
		<label for="loginCredential"><?php echo htmlspecialchars($lang['strvaultsavedlogin']); ?></label>
		<select id="loginCredential" name="loginCredential" data-vault-select
			data-listbox-label="<?php echo htmlspecialchars(sprintf($lang['strvaultsavedfor'], isset($server_info['database']) ? $server_info['database'] : ($server_info['desc'] ?? ''))); ?>"
			data-fix-text="<?php echo htmlspecialchars($lang['strvaultupdatepassword']); ?>"
			data-warning-text="<?php echo htmlspecialchars($lang['strvaultwarning']); ?>">
<?php
		foreach (array('personal' => $lang['strvaultmine'], 'shared' => $lang['strvaultsharedwithme']) as $kind => $group_label) {
			if (!$login_groups[$kind]) continue;
			echo "\t\t\t<optgroup label=\"", htmlspecialchars($group_label), "\">\n";
			foreach ($login_groups[$kind] as $row) {
				$failed = $row['last_status'] === 'auth_failed';
				$access = $login_access[$row['access_label']] ?? $row['access_label'];
				// The second line of the item, as on board 1.
				$meta = array($row['pg_username']);
				if ($failed)
					$meta[] = $lang['strvaultmetafailed'];
				elseif ($kind === 'personal')
					$meta[] = sprintf($lang['strvaultmetalastused'], VaultFormat::ago($row['last_used_at'], $login_now));
				if ($kind === 'shared') {
					$meta[] = $row['via'] === 'you'
						? $lang['strvaultmetayou']
						: sprintf($lang['strvaultmetagroup'], substr((string) $row['via'], strlen('group:')));
					$meta[] = $row['expires_at'] === null
						? $lang['strvaultmetanoexpiry']
						: sprintf($lang['strvaultmetaexpires'], VaultFormat::date($row['expires_at']));
				}
				echo "\t\t\t\t<option value=\"", htmlspecialchars($row['id']), "\"",
					" data-label=\"", htmlspecialchars($row['label']), "\"",
					" data-user=\"", htmlspecialchars($row['pg_username']), "\"",
					" data-access=\"", htmlspecialchars($row['access_label']), "\"",
					" data-access-text=\"", htmlspecialchars($access), "\"",
					" data-meta=\"", htmlspecialchars(implode(' · ', $meta)), "\"";
				if ($failed) {
					echo " data-failed=\"1\"";
					if ($kind === 'personal')
						echo " data-fix=\"", htmlspecialchars('vault.php?action=password&id=' . rawurlencode($row['id'])), "\"";
				}
				echo ">", htmlspecialchars($row['label'] . ' — ' . $row['pg_username'] . ' (' . $access . ')'), "</option>\n";
			}
			echo "\t\t\t</optgroup>\n";
		}
?>
		</select>
	</div>
	<p class="vault-lock-note"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false"><rect x="5" y="11" width="14" height="10" rx="2"></rect><path d="M8 11V7a4 4 0 0 1 8 0v4"></path></svg><span><?php echo htmlspecialchars($lang['strvaultlocknote']); ?></span></p>
	<p><button type="submit" class="vault-primary"><?php echo htmlspecialchars($lang['strvaultlogin']); ?></button></p>
</form>
</section>

<div class="vault-divider"><span><?php echo htmlspecialchars($lang['strvaultormanual']); ?></span></div>
<?php
	}
?>

<section class="vault-login-section" aria-labelledby="vault-manual-h">
<h3 id="vault-manual-h"><?php echo htmlspecialchars($lang['strvaultmanual']); ?></h3>
<form id="login_form" action="<?php echo htmlspecialchars($login_action); ?>" method="post" name="login_form">
<?php echo $login_hidden; ?>
	<div class="vault-login-grid">
		<div class="vault-field">
			<label for="loginUsername"><?php echo $lang['strusername']; ?></label>
			<input type="text" id="loginUsername" name="loginUsername" autocomplete="username" value="<?php echo htmlspecialchars($login_username); ?>" size="24" />
		</div>
		<div class="vault-field">
			<label for="loginPassword"><?php echo $lang['strpassword']; ?></label>
			<input id="loginPassword" type="password" autocomplete="current-password" name="loginPassword_<?php echo $md5_server; ?>" size="24" />
		</div>
	</div>
<?php if ($login_vault !== null && $login_key !== '') : ?>
	<div class="vault-save">
		<p class="vault-save-check"><input type="checkbox" id="loginSave" name="loginSave" /><label for="loginSave"><?php echo htmlspecialchars($lang['strvaultsavethis']); ?></label></p>
		<div class="vault-field vault-save-label">
			<label for="loginSaveLabel"><?php echo htmlspecialchars($lang['strvaultsavelabel']); ?></label>
			<input type="text" id="loginSaveLabel" name="loginSaveLabel" maxlength="100" placeholder="<?php echo htmlspecialchars($lang['strvaultsaveplaceholder']); ?>" />
			<span class="vault-hint"><?php echo htmlspecialchars(sprintf($lang['strvaultsavehint'], $login_where[0], $login_where[1])); ?></span>
		</div>
	</div>
<?php endif; ?>
<?php if (count($misc->getLoginTargets()) > 1) : ?>
	<p><input type="checkbox" id="loginShared" name="loginShared" <?php echo isset($_POST['loginShared']) ? 'checked="checked"' : '' ?> /><label for="loginShared"><?php echo $lang['strtrycred'] ?></label></p>
<?php endif; ?>
	<p><input type="submit" name="loginSubmit" value="<?php echo htmlspecialchars($lang['strvaultlogin']); ?>" /></p>
</form>
</section>

<script type="text/javascript">
	(function () {
		var form = document.getElementById('login_form');
		var uname = document.getElementById('loginUsername');
		var pword = document.getElementById('loginPassword');
		if (!form || !uname || !pword) return;
		if (uname.value == "") {
			uname.focus();
		} else {
			pword.focus();
		}
		// With "Save this login" ticked the vault keeps the password, so
		// the browser shouldn't offer to store it as well.
		var save = document.getElementById('loginSave');
		if (save) {
			var sync = function () {
				pword.setAttribute('autocomplete', save.checked ? 'off' : 'current-password');
			};
			save.addEventListener('change', sync);
			sync();
		}
	})();
</script>

<?php
	// Output footer
	$misc->printFooter();
?>

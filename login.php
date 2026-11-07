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

	$misc->printHeader($lang['strlogin']);
	$misc->printBody();
	$misc->printTrail('root');

	$server = (isset($_REQUEST['server']) && is_scalar($_REQUEST['server'])) ? (string) $_REQUEST['server'] : '';

	$server_info = $misc->getServerInfo($server);

	$misc->printTitle(sprintf($lang['strlogintitle'], $server_info['desc'] ?? ''));

	if (isset($msg)) {
		if (!empty($loginErrorReason)) {
			// A failed connection: say why in plain words. The server's own
			// message (host, port, addresses) goes to the log, not the page.
			echo "<div class=\"message error login-error\" role=\"alert\"><p><strong>", htmlspecialchars($msg), "</strong>";
			echo " ", htmlspecialchars($loginErrorReason), "</p>\n";
			echo "</div>\n";
		} else {
			$misc->printMsg($msg);
		}
	}

	$md5_server = md5($server);
?>

<form id="login_form" action="redirect.php" method="post" name="login_form">
<?php
	if (!empty($_POST)) $vars =& $_POST;
	else $vars =& $_GET;
	// Carry over where the user was going, never an action: a link that
	// says action=drop must not drop anything once they log in.
	foreach (Misc::LOGIN_PASSTHROUGH as $key) {
		if (!isset($vars[$key]) || !is_scalar($vars[$key])) continue;
		echo "<input type=\"hidden\" name=\"", htmlspecialchars($key), "\" value=\"", htmlspecialchars((string) $vars[$key]), "\" />\n";
	}
?>
	<input type="hidden" name="ppa_csrf" value="<?php echo htmlspecialchars($misc->csrfToken()); ?>" />
	<input type="hidden" name="loginServer" value="<?php echo htmlspecialchars($server); ?>" />
	<table class="navbar login">
		<tr>
			<td><label for="loginUsername"><?php echo $lang['strusername']; ?></label></td>
			<td><input type="text" id="loginUsername" name="loginUsername" autocomplete="username" value="<?php if (isset($_POST['loginUsername']) && is_scalar($_POST['loginUsername'])) echo htmlspecialchars((string) $_POST['loginUsername']); ?>" size="24" /></td>
		</tr>
		<tr>
			<td><label for="loginPassword"><?php echo $lang['strpassword']; ?></label></td>
			<td><input id="loginPassword" type="password" autocomplete="current-password" name="loginPassword_<?php echo $md5_server; ?>" size="24" /></td>
		</tr>
	</table>
<?php if (count($misc->getLoginTargets()) > 1) : ?>
	<p><input type="checkbox" id="loginShared" name="loginShared" <?php echo isset($_POST['loginShared']) ? 'checked="checked"' : '' ?> /><label for="loginShared"><?php echo $lang['strtrycred'] ?></label></p>
<?php endif; ?>
	<p><input type="submit" name="loginSubmit" value="<?php echo $lang['strlogin']; ?>" /></p>
</form>

<script type="text/javascript">
	var uname = document.login_form.loginUsername;
	var pword = document.login_form.loginPassword_<?php echo $md5_server; ?>;
	if (uname.value == "") {
		uname.focus();
	} else {
		pword.focus();
	}
</script>

<?php
	// Output footer
	$misc->printFooter();
?>

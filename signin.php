<?php

	/**
	 * Sign-in page for local mode: an app account, not a database login.
	 * The form posts back here and lib.inc.php (Vault::handleAuthPost)
	 * checks it.
	 */

	$_no_auth = $_no_db_connection = $_no_shell = true;
	include_once('./libraries/lib.inc.php');

	$signin_next = Vault::safeNext(isset($_GET['next']) && is_string($_GET['next']) ? $_GET['next'] : '');

	// Signed in already (or sso mode): nothing to do here.
	if ($vault->identity !== null) {
		Vault::redirect($signin_next !== null ? $signin_next : 'intro.php');
	}

	$signin_flash = isset($_SESSION['ppa_flash']) && is_string($_SESSION['ppa_flash']) ? $_SESSION['ppa_flash'] : '';
	unset($_SESSION['ppa_flash']);

	$misc->printHeader($lang['strvaultsignin']);
	$misc->printBody('ppa-signin');
?>
<header class="signin-head">
	<div class="signin-app"><?php echo htmlspecialchars($appName) ?></div>
	<div class="signin-version"><?php echo htmlspecialchars("{$appName} {$appVersion}") ?></div>
</header>
<main class="signin-main">
	<form method="post" action="signin.php" class="signin-card">
		<?php echo $misc->csrfField() ?>
<?php if ($signin_next !== null) { ?>
		<input type="hidden" name="next" value="<?php echo htmlspecialchars($signin_next) ?>" />
<?php } ?>
		<div class="signin-card-head">
			<h1><?php echo htmlspecialchars($lang['strvaultsignin']) ?></h1>
			<div><?php echo htmlspecialchars($lang['strvaultsigninintro']) ?></div>
		</div>
		<div class="signin-card-body">
			<div class="signin-field">
				<label for="signin-username"><?php echo htmlspecialchars($lang['strusername']) ?></label>
				<input id="signin-username" name="username" type="text" autocomplete="username" autocapitalize="none" spellcheck="false" required autofocus />
			</div>
			<div class="signin-field">
				<label for="signin-password"><?php echo htmlspecialchars($lang['strpassword']) ?></label>
				<input id="signin-password" name="password" type="password" autocomplete="current-password" required />
			</div>
			<button type="submit"><?php echo htmlspecialchars($lang['strvaultsignin']) ?></button>
<?php if ($signin_flash !== '') { ?>
			<div class="signin-alert" role="alert">
				<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false"><circle cx="12" cy="12" r="9"></circle><path d="M12 8v5"></path><path d="M12 16h.01"></path></svg>
				<span><?php echo htmlspecialchars($signin_flash) ?></span>
			</div>
<?php } ?>
			<div class="signin-hint"><?php echo htmlspecialchars($lang['strvaultforgotpassword']) ?></div>
		</div>
	</form>
</main>
<?php
	$_no_bottom_link = true;
	$misc->printFooter();

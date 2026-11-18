<?php

	/**
	 * Sign out of the app. The POST (from the top bar) is handled in
	 * lib.inc.php by Vault::handleAuthPost: it clears the session and sends
	 * you to signin.php (local mode) or AUTH_SIGNOUT_URL (sso mode).
	 * A GET changes nothing.
	 */

	$_no_db_connection = true;
	include_once('./libraries/lib.inc.php');

	Vault::redirect('intro.php');

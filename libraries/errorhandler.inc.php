<?php

/**
 * Overrides default ADODB error handler to provide nicer error handling.
 *
 * $Id: errorhandler.inc.php,v 1.20 2005/11/13 08:39:49 chriskl Exp $
 */

if (! defined('ADODB_ERROR_HANDLER'))
	define('ADODB_ERROR_HANDLER','Error_Handler');

/**
 * Default Error Handler. This will be called with the following params
 *
 * @param $dbms		the RDBMS you are connecting to
 * @param $fn		the name of the calling function (in uppercase)
 * @param $errno		the native error number from the database
 * @param $errmsg	the native error msg from the database
 * @param $p1		$fn specific parameter - see below
 * @param $P2		$fn specific parameter - see below
 */
/**
 * The server's message for a failed connection, without PHP's prefix,
 * or '' when there is none.
 */
function loginErrorDetail($errmsg) {
	$last = error_get_last();
	$text = '';
	if ($last && preg_match('/pg_p?connect\(\)/', $last['message'])) {
		$text = $last['message'];
	} elseif (is_string($errmsg) && $errmsg !== 'Database connection failed') {
		$text = $errmsg;
	}
	// PHP's message may come HTML-escaped (html_errors); it is printed escaped.
	$text = html_entity_decode(strip_tags($text), ENT_QUOTES, 'UTF-8');
	$text = preg_replace('/^.*?Unable to connect to PostgreSQL server:\s*/s', '', $text);
	$text = preg_replace('/^pg_p?connect\(\):\s*/', '', $text);
	return trim($text);
}

/**
 * A plain-language reason for a failed login, picked from the server's
 * message, or '' when it doesn't match a case we know.
 */
function loginErrorReason($detail) {
	global $lang;
	$cases = array(
		'/password authentication failed|authentication failed for user|no password supplied|password is required/i' => 'strloginbadpassword',
		'/no pg_hba\.conf entry|pg_hba\.conf rejects/i' => 'strloginhba',
		'/role "[^"]*" does not exist/i' => 'strloginnorole',
		'/database "[^"]*" does not exist/i' => 'strloginnodb',
		'/could not translate host name|Name or service not known|nodename nor servname/i' => 'strloginnohost',
		'/Connection refused|timeout expired|timed out|No route to host|Network is unreachable|could not connect to server/i' => 'strloginunreachable',
		'/SSL|certificate/i' => 'strloginssl',
		'/too many (clients|connections)|remaining connection slots/i' => 'strlogintoomany',
		'/not permitted to log in/i' => 'strloginnologin',
	);
	foreach ($cases as $re => $key) {
		if (preg_match($re, $detail) && isset($lang[$key])) return $lang[$key];
	}
	return '';
}

function Error_Handler($dbms, $fn, $errno, $errmsg, $p1=false, $p2=false)
{
	global $lang, $conf;
	global $misc, $appName, $appVersion, $appLangFiles;

	switch($fn) {
	case 'EXECUTE':
		$sql = $p1;
		$inputparams = $p2;
		
		$s = "<p><b>{$lang['strsqlerror']}</b><br />" . $misc->printVal($errmsg,'errormsg') . "</p>
		      <p><b>{$lang['strinstatement']}</b><br />" . $misc->printVal($sql) . "</p>
		";
		echo "<table class=\"error\" cellpadding=\"5\"><tr><td>{$s}</td></tr></table><br />\n";

		break;

	case 'PCONNECT':
	case 'CONNECT':
		$_failed = true;
		global $_reload_browser;
		$_reload_browser = true;
		unset($_SESSION['sharedUsername']);
		unset($_SESSION['sharedPassword']);
		unset($_SESSION['webdbLogin'][$_REQUEST['server']]);
		$msg = $lang['strloginfailed'];
		// ADOdb only keeps "Database connection failed"; the server's own
		// reason is in the warning pg_connect() raised just before.
		$loginErrorDetail = loginErrorDetail($errmsg);
		$loginErrorReason = loginErrorReason($loginErrorDetail);
		if ($loginErrorDetail !== '')
			error_log('phpPgAdmin login failed: ' . preg_replace('/\s+/', ' ', $loginErrorDetail));
		include('./login.php');
		exit;
		break;
	default:
		$s = htmlspecialchars("$dbms error: [$errno: $errmsg] in $fn(" . (is_scalar($p1) ? $p1 : '') . ", " . (is_scalar($p2) ? $p2 : '') . ")") . "\n";
		echo "<table class=\"error\" cellpadding=\"5\"><tr><td>{$s}</td></tr></table><br />\n";
		break;
	}
	/*
	* Log connection error somewhere
	*	0 message is sent to PHP's system logger, using the Operating System's system
	*		logging mechanism or a file, depending on what the error_log configuration
	*		directive is set to.
	*	1 message is sent by email to the address in the destination parameter.
	*		This is the only message type where the fourth parameter, extra_headers is used.
	*		This message type uses the same internal function as mail() does.
	*	2 message is sent through the PHP debugging connection.
	*		This option is only available if remote debugging has been enabled.
	*		In this case, the destination parameter specifies the host name or IP address
	*		and optionally, port number, of the socket receiving the debug information.
	*	3 message is appended to the file destination
	*/
	if (defined('ADODB_ERROR_LOG_TYPE')) {
		$t = date('Y-m-d H:i:s');
		if (defined('ADODB_ERROR_LOG_DEST'))
			error_log("($t) $s", ADODB_ERROR_LOG_TYPE, ADODB_ERROR_LOG_DEST);
		else
			error_log("($t) $s", ADODB_ERROR_LOG_TYPE);
	}
}
?>

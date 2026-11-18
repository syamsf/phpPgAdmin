<?php

require_once('./classes/vault/VaultConnect.php');

function connect_lang() {
	global $lang;
	$lang['strloginfailed'] = 'Login failed.';
}

function test_connect_failure_never_throws_or_leaks() {
	connect_lang();
	// Nothing listens on port 1: the connection fails (or pg_connect is missing).
	$r = VaultConnect::test(array('host' => '127.0.0.1', 'port' => 1, 'sslmode' => 'disable'),
		'db1', 'app', 'Secret-pw-123', 'phppgadmin:alice');
	assert_same(false, $r['ok']);
	assert_same('', $r['version']);
	assert_true($r['reason'] !== '', 'a failure has a reason');
	assert_true(array_key_exists('reason_key', $r) && is_string($r['reason_key']), 'a failure has a reason key');
	assert_same(false, strpos(json_encode($r), 'Secret-pw-123'), 'the password is in the result');
	assert_same(false, strpos(json_encode($r), '127.0.0.1'), 'libpq text is in the result');
}

function test_connect_bad_sslmode_is_refused_without_connecting() {
	connect_lang();
	$r = VaultConnect::test(array('host' => 'x', 'port' => 5432, 'sslmode' => 'bogus'), 'db1', 'app', 'pw', 'a');
	assert_same(array('ok' => false, 'reason' => 'Login failed.', 'reason_key' => '', 'version' => ''), $r);
}

function test_connect_reason_key_from_the_server_message() {
	connect_lang();
	global $lang;
	$lang['strloginbadpassword'] = 'The password was wrong.';
	if (!function_exists('loginErrorReasonKey')) {
		require_once('./libraries/errorhandler.inc.php');
	}
	// Without pg_connect (the unit-test image) or a server there is no
	// message to match: the key is '' and the reason the generic text.
	$r = VaultConnect::test(array('host' => '127.0.0.1', 'port' => 1, 'sslmode' => 'disable'), 'db1', 'app', 'pw', 'a');
	assert_true(in_array($r['reason_key'], array('', 'strloginunreachable'), true), 'reason_key is ' . $r['reason_key']);
	assert_same('strloginbadpassword', loginErrorReasonKey('FATAL:  password authentication failed for user "app"'));
}

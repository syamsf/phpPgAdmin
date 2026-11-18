<?php

require_once('./classes/vault/Vault.php');

function test_login_lock_message_singular_and_plural() {
	assert_same('Too many failed logins. Try again in 1 minute.', Vault::loginLockMessage(1));
	assert_same('Too many failed logins. Try again in 1 minute.', Vault::loginLockMessage(60));
	assert_same('Too many failed logins. Try again in 2 minutes.', Vault::loginLockMessage(61));
	assert_same('Too many failed logins. Try again in 5 minutes.', Vault::loginLockMessage(300));
}

function test_safe_next_printable_ascii_only() {
	assert_same('intro.php', Vault::safeNext('intro.php'));
	assert_same('servers.php?action=tree&x=%20y', Vault::safeNext('servers.php?action=tree&x=%20y'));
	foreach (array("intro.php?a=\x00", "intro.php?a=\x01b", "intro.php?a=\x7f", "intro.php?a=\r\nX-Bad: 1",
			"intro.php?a=b c", "intro.php?a=\xc3\xa9", "https://example.com/", "signin.php?next=x") as $next) {
		assert_same(null, Vault::safeNext($next), 'accepted ' . json_encode($next, JSON_INVALID_UTF8_SUBSTITUTE));
	}
}

/**
 * Runs $code in a fresh PHP (the repo root as the current directory, Vault.php
 * loaded) and returns array(stdout, stderr). PHP's log goes to stderr.
 */
function vault_child(string $code): array {
	// A script file, not php -r: -r never calls an exception handler.
	$script = unit_tmp() . '/child.php';
	file_put_contents($script, '<?php require ' . var_export(getcwd() . '/classes/vault/Vault.php', true) . '; ' . $code);
	$cmd = array(PHP_BINARY, '-d', 'display_errors=0', '-d', 'log_errors=1', '-d', 'error_log=/dev/stderr',
		'-d', 'zend.exception_ignore_args=1', $script);
	$proc = proc_open($cmd, array(1 => array('pipe', 'w'), 2 => array('pipe', 'w')), $pipes, getcwd());
	$out = stream_get_contents($pipes[1]);
	$err = stream_get_contents($pipes[2]);
	fclose($pipes[1]);
	fclose($pipes[2]);
	proc_close($proc);
	return array($out, $err);
}

function test_uncaught_vault_errors_show_a_generic_page() {
	$secret = '/data/secret-dir/vault.sqlite';
	foreach (array('PDOException("SQLSTATE[HY000] [14] unable to open database file ' . $secret . '")',
			'VaultError("Can\'t open the vault database ' . $secret . ': no")') as $new) {
		list($out, $err) = vault_child('set_exception_handler(array("Vault", "uncaught")); throw new ' . $new . ';');
		assert_true(strpos($out, 'The login vault is unavailable.') !== false, 'no generic page: ' . $out);
		assert_true(strpos($out, $secret) === false && strpos($out, 'SQLSTATE') === false, 'the page holds the detail: ' . $out);
		assert_true(strpos($err, $secret) !== false, 'the log lacks the detail: ' . $err);
	}
}

function test_uncaught_other_exceptions_stay_fatal() {
	list($out, $err) = vault_child('set_exception_handler(array("Vault", "uncaught")); throw new RuntimeException("boom");');
	assert_true(strpos($out, 'login vault') === false, 'a generic vault page for another error: ' . $out);
	assert_true(strpos($err, 'Uncaught RuntimeException: boom') !== false, 'not logged as uncaught: ' . $err);
}

function test_unavailable_hides_the_detail() {
	list($out, $err) = vault_child('Vault::unavailable(new VaultError("VAULT_KEY_FILE /run/secrets/key can\'t be read."));');
	assert_true(strpos($out, 'The login vault is unavailable.') !== false, 'no generic page: ' . $out);
	assert_true(strpos($out, '/run/secrets') === false, 'the page holds the detail: ' . $out);
	assert_true(strpos($err, '/run/secrets/key') !== false, 'the log lacks the detail: ' . $err);
}

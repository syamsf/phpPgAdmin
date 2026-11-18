<?php

// Servers behind PgBouncer: no startup options, how PPA_SERVERS marks them,
// and the login reason when PgBouncer refuses the options.

require_once('./classes/Misc.php');

function test_startup_options_for_postgres() {
	$conf = array('statement_timeout' => ' 5min ');
	assert_same(array('DateStyle=ISO', 'statement_timeout=5min'), Misc::startupOptions(array('host' => 'db'), $conf));
	assert_same(array('DateStyle=ISO', 'bytea_output=escape', 'statement_timeout=5min'),
		Misc::startupOptions(array('host' => 'db', 'pgVersion' => '16.4'), $conf));
	assert_same(array('DateStyle=ISO'), Misc::startupOptions(array('pgVersion' => '8.4'), array('statement_timeout' => '')));
}

function test_startup_options_none_behind_pgbouncer() {
	$conf = array('statement_timeout' => '5min');
	// Neither the timeout nor bytea_output (once the version is known):
	// PgBouncer refuses both before it checks the password.
	assert_same(array(), Misc::startupOptions(array('pgbouncer' => true), $conf));
	assert_same(array(), Misc::startupOptions(array('pgbouncer' => true, 'pgVersion' => '16.4'), $conf));
	assert_same(array('DateStyle=ISO', 'statement_timeout=5min'), Misc::startupOptions(array('pgbouncer' => false), $conf));
}

function test_startup_options_invalid_timeout_is_skipped() {
	$warned = '';
	set_error_handler(function ($no, $str) use (&$warned) {
		$warned = $str;
		return true;
	});
	try {
		$out = Misc::startupOptions(array(), array('statement_timeout' => '5 minutes; drop'));
	} finally {
		restore_error_handler();
	}
	assert_same(array('DateStyle=ISO'), $out);
	assert_true(strpos($warned, 'statement_timeout') !== false, 'warned: ' . $warned);
}

/** ppa_parse_servers() from the Docker config, included without touching the real $conf. */
function pgb_parse(string $list): array {
	if (!function_exists('ppa_parse_servers')) {
		(function () {
			$conf = array();
			include './docker/config.inc.php';
		})();
	}
	return ppa_parse_servers($list);
}

function test_ppa_servers_pgbouncer_flag() {
	assert_same(array(array('desc' => 'OBS', 'host' => '10.10.150.141', 'port' => 6432, 'pgbouncer' => true)),
		pgb_parse('OBS=10.10.150.141:6432?pgbouncer=1'));
	assert_same(array(array('desc' => 'A', 'host' => 'h', 'port' => 6432, 'sslmode' => 'require', 'pgbouncer' => true)),
		pgb_parse('A=h:6432?sslmode=require&pgbouncer'));
	assert_same(array(array('desc' => 'Shop', 'host' => 'db', 'port' => 5432, 'sslmode' => 'verify-full', 'pgbouncer' => true,
		'databases' => array('a', 'b'))), pgb_parse('Shop=db:5432/a+b?pgbouncer=on&sslmode=verify-full'));
	assert_same(array(array('desc' => 'P', 'host' => 'db', 'port' => 5432)), pgb_parse('P=db?pgbouncer=0'));
}

function test_ppa_servers_sslmode_alone_unchanged() {
	assert_same(array(
		array('desc' => 'Test', 'host' => 'db', 'port' => 5432),
		array('desc' => 'Scoped', 'host' => 'db', 'port' => 5432, 'databases' => array('ppa_other', 'ppa_test')),
		array('desc' => 'Tls', 'host' => 'db', 'port' => 5432, 'sslmode' => 'require'),
		array('desc' => '::1', 'host' => '::1', 'port' => 5433),
	), pgb_parse('Test=db:5432 Scoped=db:5432/ppa_other+ppa_test Tls=db:5432?sslmode=require [::1]:5433'));
}

function test_ppa_servers_unknown_setting_warns_and_is_dropped() {
	$warned = '';
	set_error_handler(function ($no, $str) use (&$warned) {
		$warned = $str;
		return true;
	});
	try {
		$out = pgb_parse('X=db:6432?pool=1');
	} finally {
		restore_error_handler();
	}
	assert_same(array(array('desc' => 'X', 'host' => 'db', 'port' => 6432)), $out);
	assert_true(strpos($warned, 'pool=1') !== false, 'warned: ' . $warned);
}

function test_pgbouncer_refusal_has_its_own_reason() {
	global $lang;
	$lang['strloginpgbouncer'] = 'PgBouncer.';
	if (!function_exists('loginErrorReasonKey')) {
		require_once('./libraries/errorhandler.inc.php');
	}
	// What PgBouncer sends for a startup option it doesn't track.
	assert_same('strloginpgbouncer', loginErrorReasonKey('ERROR:  unsupported startup parameter in options: statement_timeout'));
	assert_same('strloginpgbouncer', loginErrorReasonKey('FATAL:  unsupported startup parameter: options'));
}

<?php

// Limits on the pg_dump / pg_dumpall that dbexport.php runs, and turning
// them off with PPA_PG_DUMP=false.

require_once('./classes/Misc.php');

function test_pg_dump_command_unchanged_without_limits() {
	assert_same('/usr/bin/pg_dump -a', Misc::pgDumpCommand('/usr/bin/pg_dump -a', array()));
	assert_same('/usr/bin/pg_dump -a', Misc::pgDumpCommand('/usr/bin/pg_dump -a',
		array('pg_dump_lock_wait_timeout' => '', 'pg_dump_max_minutes' => 0)));
}

function test_pg_dump_lock_wait_timeout() {
	assert_same('/usr/bin/pg_dump -a --lock-wait-timeout=30s',
		Misc::pgDumpCommand('/usr/bin/pg_dump -a', array('pg_dump_lock_wait_timeout' => ' 30s ')));
	assert_same('/usr/bin/pg_dumpall --lock-wait-timeout=2min',
		Misc::pgDumpCommand('/usr/bin/pg_dumpall', array('pg_dump_lock_wait_timeout' => '2min')));
}

function test_pg_dump_invalid_lock_wait_timeout_is_skipped() {
	$warned = '';
	set_error_handler(function ($no, $str) use (&$warned) {
		$warned = $str;
		return true;
	});
	try {
		$out = Misc::pgDumpCommand('/usr/bin/pg_dump', array('pg_dump_lock_wait_timeout' => '30s; rm -rf /'));
	} finally {
		restore_error_handler();
	}
	assert_same('/usr/bin/pg_dump', $out);
	assert_true(strpos($warned, 'pg_dump_lock_wait_timeout') !== false, 'warned: ' . $warned);
}

function test_pg_dump_max_minutes_wraps_in_timeout() {
	assert_same('timeout --signal=TERM 600 /usr/bin/pg_dump -a',
		Misc::pgDumpCommand('/usr/bin/pg_dump -a', array('pg_dump_max_minutes' => '10')));
	assert_same('timeout --signal=TERM 300 /usr/bin/pg_dump -s --lock-wait-timeout=30s',
		Misc::pgDumpCommand('/usr/bin/pg_dump -s', array('pg_dump_max_minutes' => 5, 'pg_dump_lock_wait_timeout' => '30s')));
	// 0, negative or garbage: no limit.
	assert_same('/usr/bin/pg_dump', Misc::pgDumpCommand('/usr/bin/pg_dump', array('pg_dump_max_minutes' => -3)));
	assert_same('/usr/bin/pg_dump', Misc::pgDumpCommand('/usr/bin/pg_dump', array('pg_dump_max_minutes' => 'ten')));
}

function test_pg_dump_timed_out() {
	// coreutils timeout exits 124 when it had to stop the command.
	assert_true(Misc::pgDumpTimedOut(124, array('pg_dump_max_minutes' => 10)));
	assert_true(!Misc::pgDumpTimedOut(0, array('pg_dump_max_minutes' => 10)));
	assert_true(!Misc::pgDumpTimedOut(124, array('pg_dump_max_minutes' => 0)), 'no limit set: 124 is pg_dump\'s own');
}

/** $conf from the Docker config with these environment variables set. */
function pgdump_docker_conf(array $env): array {
	$old = array();
	foreach ($env as $k => $v) {
		$old[$k] = getenv($k);
		putenv($v === null ? $k : "{$k}={$v}");
	}
	try {
		return (function () {
			$conf = array();
			include './docker/config.inc.php';
			return $conf;
		})();
	} finally {
		foreach ($old as $k => $v) putenv($v === false ? $k : "{$k}={$v}");
	}
}

function test_docker_config_pg_dump_on_by_default() {
	$conf = pgdump_docker_conf(array('PPA_SERVERS' => 'A=db:5432', 'PPA_PG_DUMP' => null,
		'PPA_PG_DUMP_LOCK_WAIT_TIMEOUT' => null, 'PPA_PG_DUMP_MAX_MINUTES' => null));
	assert_same('/usr/bin/pg_dump', $conf['servers'][0]['pg_dump_path']);
	assert_same('/usr/bin/pg_dumpall', $conf['servers'][0]['pg_dumpall_path']);
	assert_same('/usr/bin/pg_dump', $conf['vault']['ui_defaults']['pg_dump_path']);
	assert_same('', $conf['pg_dump_lock_wait_timeout']);
	assert_same(0, $conf['pg_dump_max_minutes']);
}

function test_docker_config_pg_dump_off() {
	$conf = pgdump_docker_conf(array('PPA_SERVERS' => 'A=db:5432, B=db2', 'PPA_PG_DUMP' => 'false'));
	foreach ($conf['servers'] as $server) {
		assert_same('', $server['pg_dump_path']);
		assert_same('', $server['pg_dumpall_path']);
	}
	// Servers added on "Manage servers" too.
	assert_same('', $conf['vault']['ui_defaults']['pg_dump_path']);
	assert_same('', $conf['vault']['ui_defaults']['pg_dumpall_path']);
}

function test_docker_config_pg_dump_limits() {
	$conf = pgdump_docker_conf(array('PPA_SERVERS' => 'A=db', 'PPA_PG_DUMP_LOCK_WAIT_TIMEOUT' => '30s',
		'PPA_PG_DUMP_MAX_MINUTES' => '15'));
	assert_same('30s', $conf['pg_dump_lock_wait_timeout']);
	assert_same(15, $conf['pg_dump_max_minutes']);
}

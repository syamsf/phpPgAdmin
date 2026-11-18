<?php
// Tiny unit-test runner. From the repo root:
//   php tests/unit/run.php [file-filter]
// Requires every tests/unit/*Test.php and calls every function named test_*.

chdir(dirname(__DIR__, 2));

class UnitFailure extends Exception {}

$GLOBALS['unit_tmp_dirs'] = [];

function assert_same($expected, $actual, string $msg = ''): void {
	if ($expected !== $actual) {
		throw new UnitFailure(($msg !== '' ? $msg . ': ' : '') . 'expected '
			. var_export($expected, true) . ', got ' . var_export($actual, true));
	}
}

function assert_true($cond, string $msg = ''): void {
	if ($cond !== true) {
		throw new UnitFailure($msg !== '' ? $msg : 'expected true');
	}
}

function assert_throws(string $class, callable $fn, string $msgContains = ''): void {
	try {
		$fn();
	} catch (Throwable $e) {
		if (!($e instanceof $class)) {
			throw new UnitFailure("expected $class, got " . get_class($e) . ': ' . $e->getMessage());
		}
		if ($msgContains !== '' && strpos($e->getMessage(), $msgContains) === false) {
			throw new UnitFailure("message '" . $e->getMessage() . "' does not contain '$msgContains'");
		}
		return;
	}
	throw new UnitFailure("expected $class, nothing thrown");
}

/** A fresh temp directory (under the system temp dir), removed after the test. */
function unit_tmp(): string {
	$dir = sys_get_temp_dir() . '/ppa-unit-' . bin2hex(random_bytes(8));
	mkdir($dir, 0700, true);
	$GLOBALS['unit_tmp_dirs'][] = $dir;
	return $dir;
}

function unit_rm(string $path): void {
	if (is_dir($path) && !is_link($path)) {
		foreach (scandir($path) as $f) {
			if ($f !== '.' && $f !== '..') {
				unit_rm($path . '/' . $f);
			}
		}
		@rmdir($path);
	} else {
		@unlink($path);
	}
}

$filter = $argv[1] ?? '';
$files = glob(__DIR__ . '/*Test.php');
sort($files);
$before = get_defined_functions()['user'];
foreach ($files as $file) {
	if ($filter !== '' && strpos(basename($file), $filter) === false) {
		continue;
	}
	require_once $file;
}
$tests = array_values(array_filter(
	array_diff(get_defined_functions()['user'], $before),
	function ($f) { return strpos($f, 'test_') === 0; }
));

$failed = 0;
foreach ($tests as $name) {
	try {
		$name();
		echo "ok    $name\n";
	} catch (Throwable $e) {
		$failed++;
		echo "FAIL  $name: " . $e->getMessage() . "\n";
	}
	foreach ($GLOBALS['unit_tmp_dirs'] as $d) {
		unit_rm($d);
	}
	$GLOBALS['unit_tmp_dirs'] = [];
}
echo count($tests) . " tests, $failed failed\n";
exit($failed ? 1 : 0);

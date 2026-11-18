<?php

/**
 * Tries a Postgres login without keeping it. Pages that take a password
 * (the update-password dialog, later the shared logins) use it to check the
 * password before storing it.
 */
class VaultConnect {

	/**
	 * Connects once and closes again. Never throws for a failed connection
	 * and never returns the password or libpq's own text: on failure
	 * 'reason' is a plain-language reason from loginErrorReason(), or the
	 * generic "Login failed.", and 'reason_key' its $lang key from
	 * loginErrorReasonKey() ('' when none matched), for the audit log.
	 * @param $server array host, port, sslmode and optionally sslrootcert
	 * @return array ['ok' => bool, 'reason' => string, 'reason_key' => string, 'version' => string]
	 */
	public static function test(array $server, string $database, string $user, string $password, string $appName): array {
		global $lang;

		if (!class_exists('Connection', false)) {
			include_once('./classes/database/Connection.php');
		}
		$generic = isset($lang['strloginfailed']) ? $lang['strloginfailed'] : 'Login failed.';
		$sslmode = isset($server['sslmode']) ? $server['sslmode'] : '';
		if (!Connection::validSslmode($sslmode)) {
			return array('ok' => false, 'reason' => $generic, 'reason_key' => '', 'version' => '');
		}

		$info = Connection::conninfo(
			isset($server['host']) ? $server['host'] : '',
			isset($server['port']) ? $server['port'] : '',
			$sslmode, $user, $password, $database,
			isset($server['sslrootcert']) ? $server['sslrootcert'] : ''
		) . ' connect_timeout=10 application_name=' . Connection::conninfoValue($appName);

		// Catch the warning pg_connect() raises for a failed login, so it
		// reaches neither the page nor the log.
		$warning = '';
		set_error_handler(function ($no, $str) use (&$warning) {
			$warning = (string) $str;
			return true;
		});
		try {
			$conn = @pg_connect($info, PGSQL_CONNECT_FORCE_NEW);
		} catch (Throwable $e) {
			$conn = false;
		}
		restore_error_handler();

		if (!$conn) {
			$key = function_exists('loginErrorReasonKey') ? (string)loginErrorReasonKey($warning) : '';
			$reason = ($key !== '' && isset($lang[$key])) ? $lang[$key] : '';
			return array('ok' => false, 'reason' => $reason !== '' ? $reason : $generic, 'reason_key' => $key, 'version' => '');
		}
		$version = '';
		$v = @pg_version($conn);
		if (is_array($v) && isset($v['server'])) {
			$version = (string) $v['server'];
		}
		pg_close($conn);
		return array('ok' => true, 'reason' => '', 'reason_key' => '', 'version' => $version);
	}
}

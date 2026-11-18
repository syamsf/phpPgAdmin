<?php

/*
 * Config used by the Docker image. Settings come from environment variables,
 * see README.md for the list. For anything this file can't express (server
 * groups, per-server themes, different sslmode per server) mount your own
 * config over /var/www/html/conf/config.inc.php.
 */

// Guarded in case the config ever gets included twice.
if (!function_exists('ppa_env')) {
	function ppa_env($name, $default = null)
	{
		$value = getenv($name);

		return ($value === false || $value === '') ? $default : $value;
	}

	function ppa_env_bool($name, $default)
	{
		$value = ppa_env($name);
		if ($value === null) {
			return $default;
		}

		return in_array(strtolower($value), array('1', 'true', 'yes', 'on'), true);
	}

	// "Production=db1.internal:5432, Staging=db2.internal, [::1]:5433"
	// A "?sslmode=require" suffix sets the sslmode of that one server (it
	// otherwise follows PPA_SSLMODE). "?pgbouncer=1" marks a server behind
	// PgBouncer, which gets no startup options (see Misc::startupOptions).
	// Both together: "?sslmode=require&pgbouncer=1".
	// A "/db1+db2" suffix gives each of those databases its own login:
	// "Shop=db3.internal:5432/orders+billing"
	function ppa_parse_servers($list)
	{
		$servers = array();

		foreach (preg_split('/[\s,]+/', $list, -1, PREG_SPLIT_NO_EMPTY) as $entry) {
			$desc = null;
			if (strpos($entry, '=') !== false) {
				list($desc, $entry) = explode('=', $entry, 2);
			}

			$sslmode = null;
			$pgbouncer = false;
			if (preg_match('/\?([^?]*)$/', $entry, $m)) {
				$entry = substr($entry, 0, -strlen($m[0]));
				foreach (explode('&', $m[1]) as $setting) {
					if ($setting === '') {
						continue;
					}
					$parts = explode('=', $setting, 2);
					$value = isset($parts[1]) ? $parts[1] : null;
					if ($parts[0] === 'sslmode' && $value !== null) {
						$sslmode = $value;
					} elseif ($parts[0] === 'pgbouncer') {
						// A bare "?pgbouncer" means on too.
						$pgbouncer = $value === null
							|| in_array(strtolower($value), array('1', 'true', 'yes', 'on'), true);
					} else {
						trigger_error("PPA_SERVERS: ignoring \"{$setting}\" (use sslmode=... or pgbouncer=1)", E_USER_WARNING);
					}
				}
			}

			$databases = array();
			if (strpos($entry, '/') !== false) {
				list($entry, $dblist) = explode('/', $entry, 2);
				$databases = preg_split('/\+/', $dblist, -1, PREG_SPLIT_NO_EMPTY);
			}

			$port = 5432;
			if (preg_match('/^\[(.+)\](?::(\d+))?$/', $entry, $m)) {
				$host = $m[1];
				if (isset($m[2])) $port = (int) $m[2];
			} elseif (preg_match('/^([^:]+):(\d+)$/', $entry, $m)) {
				$host = $m[1];
				$port = (int) $m[2];
			} else {
				$host = $entry;
			}

			$server = array(
				'desc' => $desc !== null && $desc !== '' ? $desc : $host,
				'host' => $host,
				'port' => $port,
			);
			if ($sslmode !== null) {
				$server['sslmode'] = $sslmode;
			}
			if ($pgbouncer) {
				$server['pgbouncer'] = true;
			}
			if ($databases) {
				$server['databases'] = $databases;
			}
			$servers[] = $server;
		}

		return $servers;
	}
}

foreach (ppa_parse_servers(ppa_env('PPA_SERVERS', 'localhost')) as $i => $server) {
	$conf['servers'][$i] = $server + array(
		'sslmode' => ppa_env('PPA_SSLMODE', 'prefer'),
		'sslrootcert' => ppa_env('PPA_SSLROOTCERT', ''),
		'defaultdb' => ppa_env('PPA_DEFAULTDB', 'postgres'),
		'pg_dump_path' => '/usr/bin/pg_dump',
		'pg_dumpall_path' => '/usr/bin/pg_dumpall',
	);
}

$conf['default_lang'] = ppa_env('PPA_DEFAULT_LANG', 'auto');
$conf['extra_session_security'] = true;
$conf['autocomplete'] = ppa_env('PPA_AUTOCOMPLETE', 'default on');
$conf['extra_login_security'] = ppa_env_bool('PPA_EXTRA_LOGIN_SECURITY', true);
$conf['owned_only'] = ppa_env_bool('PPA_OWNED_ONLY', false);
$conf['show_comments'] = ppa_env_bool('PPA_SHOW_COMMENTS', true);
$conf['show_advanced'] = ppa_env_bool('PPA_SHOW_ADVANCED', false);
$conf['show_system'] = ppa_env_bool('PPA_SHOW_SYSTEM', false);
$conf['min_password_length'] = (int) ppa_env('PPA_MIN_PASSWORD_LENGTH', 1);
$conf['left_width'] = (int) ppa_env('PPA_LEFT_WIDTH', 200);
$conf['theme'] = ppa_env('PPA_THEME', 'default');
$conf['show_oids'] = ppa_env_bool('PPA_SHOW_OIDS', false);
$conf['max_rows'] = (int) ppa_env('PPA_MAX_ROWS', 30);
$conf['max_chars'] = (int) ppa_env('PPA_MAX_CHARS', 50);
$conf['browse_exact_count_limit'] = (int) ppa_env('PPA_BROWSE_EXACT_COUNT_LIMIT', 100000);
$conf['max_result_rows'] = (int) ppa_env('PPA_MAX_RESULT_ROWS', 1000);
$conf['use_xhtml_strict'] = false;
$conf['help_base'] = 'https://www.postgresql.org/docs/%s/';
$conf['ajax_refresh'] = (int) ppa_env('PPA_AJAX_REFRESH', 3);
// e.g. "30s" or "5min"; unset means no limit.
$conf['statement_timeout'] = ppa_env('PPA_STATEMENT_TIMEOUT', '');
$conf['plugins'] = preg_split('/[\s,]+/', ppa_env('PPA_PLUGINS', ''), -1, PREG_SPLIT_NO_EMPTY);

// Sign-in and saved logins. AUTH_MODE, AUTH_ADMIN_GROUP and a vault key have
// no defaults: without them the app refuses to start. See README.md.
$conf['vault'] = array(
	'auth_mode' => ppa_env('AUTH_MODE', ''),
	'admin_group' => ppa_env('AUTH_ADMIN_GROUP', ''),
	'trusted_proxies' => ppa_env('AUTH_TRUSTED_PROXIES', ''),
	'user_header' => ppa_env('AUTH_USER_HEADER', 'Remote-User'),
	'groups_header' => ppa_env('AUTH_GROUPS_HEADER', 'Remote-Groups'),
	'key_file' => ppa_env('VAULT_KEY_FILE', ''),
	'key' => ppa_env('VAULT_KEY', ''),
	'db_path' => ppa_env('VAULT_DB_PATH', '/data/vault.sqlite'),
	'servers_allow_ui' => ppa_env_bool('SERVERS_ALLOW_UI', true),
	'signout_url' => ppa_env('AUTH_SIGNOUT_URL', ''),
	'idle_minutes' => ppa_env('AUTH_IDLE_MINUTES', '30'),
	// Settings for servers added in the UI, which have no env of their own.
	'ui_defaults' => array(
		'pg_dump_path' => '/usr/bin/pg_dump',
		'pg_dumpall_path' => '/usr/bin/pg_dumpall',
		'sslrootcert' => ppa_env('PPA_SSLROOTCERT', ''),
	),
);

$conf['version'] = 19;

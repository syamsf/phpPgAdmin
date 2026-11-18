<?php

require_once(__DIR__ . '/VaultError.php');
require_once(__DIR__ . '/VaultAuth.php');

/**
 * Reads and checks $conf['vault']. A setting that is missing or wrong stops
 * the app with an error that names the environment variable to fix.
 */
class VaultConfig {

	/**
	 * @return array auth_mode, admin_group, trusted_proxies (list), user_header,
	 *   groups_header, key_file, key, db_path, servers_allow_ui (bool),
	 *   signout_url, idle_minutes (int), ui_defaults (array)
	 * @throws VaultError
	 */
	public static function fromConf(array $conf): array {
		$v = isset($conf['vault']) && is_array($conf['vault']) ? $conf['vault'] : array();

		$mode = strtolower(self::str($v, 'auth_mode'));
		if ($mode !== 'sso' && $mode !== 'local') {
			throw new VaultError('AUTH_MODE must be set to sso or local.');
		}

		$adminGroup = self::str($v, 'admin_group');
		if ($adminGroup === '') {
			throw new VaultError('AUTH_ADMIN_GROUP must be set to the group whose members are admins.');
		}

		$proxies = isset($v['trusted_proxies']) ? $v['trusted_proxies'] : array();
		if (!is_array($proxies)) {
			$proxies = preg_split('/[\s,]+/', (string)$proxies, -1, PREG_SPLIT_NO_EMPTY);
		}
		$proxies = array_values(array_filter(array_map('trim', array_map('strval', $proxies)), 'strlen'));
		if ($mode === 'sso') {
			if (!$proxies) {
				throw new VaultError('AUTH_TRUSTED_PROXIES must list the address of the sign-in proxy in sso mode.');
			}
			foreach ($proxies as $cidr) {
				if (VaultAuth::parseCidr($cidr) === null) {
					throw new VaultError('AUTH_TRUSTED_PROXIES holds an invalid address or CIDR: ' . $cidr);
				}
			}
		}

		$userHeader = self::str($v, 'user_header', 'Remote-User');
		$groupsHeader = self::str($v, 'groups_header', 'Remote-Groups');
		foreach (array('AUTH_USER_HEADER' => $userHeader, 'AUTH_GROUPS_HEADER' => $groupsHeader) as $name => $header) {
			if (!preg_match('/^[A-Za-z0-9-]+$/', $header)) {
				throw new VaultError($name . ' must be a header name made of letters, digits and dashes.');
			}
		}

		$dbPath = self::str($v, 'db_path');
		if ($dbPath === '') {
			throw new VaultError('VAULT_DB_PATH must be set to the path of the vault database file.');
		}

		$idle = isset($v['idle_minutes']) && $v['idle_minutes'] !== '' ? $v['idle_minutes'] : 30;
		if (!is_int($idle) && !(is_string($idle) && ctype_digit(trim($idle)))) {
			throw new VaultError('AUTH_IDLE_MINUTES must be a whole number of minutes (0 turns it off).');
		}

		return array(
			'auth_mode' => $mode,
			'admin_group' => $adminGroup,
			'trusted_proxies' => $proxies,
			'user_header' => $userHeader,
			'groups_header' => $groupsHeader,
			'key_file' => self::str($v, 'key_file'),
			'key' => self::str($v, 'key'),
			'db_path' => $dbPath,
			'servers_allow_ui' => self::bool($v, 'servers_allow_ui', true),
			'signout_url' => self::str($v, 'signout_url'),
			'idle_minutes' => max(0, (int)$idle),
			'ui_defaults' => isset($v['ui_defaults']) && is_array($v['ui_defaults']) ? $v['ui_defaults'] : array(),
		);
	}

	private static function str(array $v, string $name, string $default = ''): string {
		$value = isset($v[$name]) && is_scalar($v[$name]) ? trim((string)$v[$name]) : '';
		return $value === '' ? $default : $value;
	}

	private static function bool(array $v, string $name, bool $default): bool {
		if (!isset($v[$name]) || $v[$name] === '') {
			return $default;
		}
		if (is_bool($v[$name])) {
			return $v[$name];
		}
		return in_array(strtolower(trim((string)$v[$name])), array('1', 'true', 'yes', 'on'), true);
	}
}

<?php

require_once('./classes/vault/VaultConfig.php');
require_once('./classes/vault/VaultAuth.php');
require_once('./classes/vault/VaultIdentity.php');

function auth_cfg(array $over = array()) {
	return array_merge(array(
		'auth_mode' => 'sso',
		'admin_group' => 'role-admin',
		'trusted_proxies' => array('10.0.0.0/8'),
		'user_header' => 'Remote-User',
		'groups_header' => 'Remote-Groups',
	), $over);
}

function auth_server($user, $groups = '', $addr = '10.1.2.3') {
	return array(
		'REMOTE_ADDR' => $addr,
		'HTTP_REMOTE_USER' => $user,
		'HTTP_REMOTE_GROUPS' => $groups,
	);
}

function auth_conf(array $vault) {
	return array('vault' => array_merge(array(
		'auth_mode' => 'sso',
		'admin_group' => 'role-admin',
		'trusted_proxies' => '10.0.0.5/32',
		'db_path' => '/data/vault.sqlite',
	), $vault));
}

function test_cidr_v4() {
	assert_true(VaultAuth::ipInCidrs('10.0.0.5', array('10.0.0.0/24')), 'in /24');
	assert_same(false, VaultAuth::ipInCidrs('10.0.0.5', array('10.0.1.0/24')), 'other /24');
	assert_true(VaultAuth::ipInCidrs('10.0.0.5', array('10.0.0.5/32')), 'exact /32');
	assert_same(false, VaultAuth::ipInCidrs('10.0.0.6', array('10.0.0.5/32')), 'neighbour of /32');
	assert_true(VaultAuth::ipInCidrs('10.0.0.200', array('10.0.0.128/25')), 'partial byte');
	assert_same(false, VaultAuth::ipInCidrs('10.0.0.5', array('10.0.0.128/25')), 'partial byte, outside');
}

function test_cidr_v6() {
	assert_true(VaultAuth::ipInCidrs('::1', array('::1/128')), '::1');
	assert_true(VaultAuth::ipInCidrs('2001:db8::1', array('2001:db8::/32')), '2001:db8::/32');
	assert_same(false, VaultAuth::ipInCidrs('2001:db9::1', array('2001:db8::/32')), 'outside /32');
	assert_same(false, VaultAuth::ipInCidrs('10.0.0.5', array('::/0')), 'v4 in ::/0');
	assert_same(false, VaultAuth::ipInCidrs('::1', array('0.0.0.0/0')), 'v6 in 0.0.0.0/0');
}

function test_cidr_mapped_v4() {
	assert_true(VaultAuth::ipInCidrs('::ffff:10.0.0.5', array('10.0.0.0/8')), 'mapped');
	assert_same(false, VaultAuth::ipInCidrs('::ffff:11.0.0.5', array('10.0.0.0/8')), 'mapped, outside');
}

function test_cidr_garbage_never_matches() {
	assert_same(false, VaultAuth::ipInCidrs('', array('0.0.0.0/0')), 'empty ip');
	assert_same(false, VaultAuth::ipInCidrs('not-an-ip', array('0.0.0.0/0')), 'bad ip');
	assert_same(false, VaultAuth::ipInCidrs('10.0.0.5', array('10.0.0.0/33', 'x/8', '10.0.0.0/')), 'bad cidrs');
}

function test_parse_groups_trims() {
	assert_same(array('role-admin', 'dba'), VaultAuth::parseGroups(" role-admin, dba ,,dba"));
	assert_same(array(), VaultAuth::parseGroups(''));
}

function test_sso_untrusted() {
	$why = null;
	$id = VaultAuth::ssoIdentity(auth_server('alice', 'dba', '192.0.2.9'), auth_cfg(), $why);
	assert_same(null, $id);
	assert_same('untrusted', $why);
}

function test_sso_missing_user() {
	foreach (array('', '   ') as $user) {
		$why = null;
		assert_same(null, VaultAuth::ssoIdentity(auth_server($user), auth_cfg(), $why));
		assert_same('missing', $why);
	}
	$why = null;
	$server = auth_server('x');
	unset($server['HTTP_REMOTE_USER']);
	assert_same(null, VaultAuth::ssoIdentity($server, auth_cfg(), $why));
	assert_same('missing', $why);
}

function test_sso_rejects_long_user() {
	$why = null;
	assert_same(null, VaultAuth::ssoIdentity(auth_server(str_repeat('a', 129)), auth_cfg(), $why));
	assert_same('missing', $why);
	$why = null;
	$id = VaultAuth::ssoIdentity(auth_server(str_repeat('a', 128)), auth_cfg(), $why);
	assert_same(128, strlen($id->username));
}

function test_sso_rejects_control_chars() {
	$why = null;
	assert_same(null, VaultAuth::ssoIdentity(auth_server("ali\x01ce"), auth_cfg(), $why));
	assert_same('missing', $why);
}

function test_sso_rejects_invalid_utf8() {
	$why = null;
	assert_same(null, VaultAuth::ssoIdentity(auth_server("ali\xc3ce"), auth_cfg(), $why));
	assert_same('missing', $why);
	$id = VaultAuth::ssoIdentity(auth_server("j\xc3\xb6rg"), auth_cfg(), $why);
	assert_same("j\xc3\xb6rg", $id->username, 'valid UTF-8 is fine');
}

function test_sso_rejects_comma() {
	$why = null;
	assert_same(null, VaultAuth::ssoIdentity(auth_server('alice,role-admin'), auth_cfg(), $why));
	assert_same('missing', $why);
}

function test_sso_custom_header() {
	$why = null;
	$server = array('REMOTE_ADDR' => '10.0.0.1', 'HTTP_X_FORWARDED_USER' => 'bob');
	$id = VaultAuth::ssoIdentity($server, auth_cfg(array('user_header' => 'X-Forwarded-User')), $why);
	assert_same('bob', $id->username);
}

function test_sso_admin() {
	$why = null;
	$id = VaultAuth::ssoIdentity(auth_server(' boss ', 'dba, role-admin'), auth_cfg(), $why);
	assert_same('boss', $id->username);
	assert_same(array('dba', 'role-admin'), $id->groups);
	assert_same(true, $id->isAdmin);
	assert_same('sso', $id->mode);

	$id = VaultAuth::ssoIdentity(auth_server('boss', 'role-admins'), auth_cfg(), $why);
	assert_same(false, $id->isAdmin);
	$id = VaultAuth::ssoIdentity(auth_server('boss', 'Role-Admin'), auth_cfg(), $why);
	assert_same(false, $id->isAdmin, 'case matters');
}

function test_config_requires_mode() {
	foreach (array(null, '', 'none') as $mode) {
		$conf = auth_conf(array('auth_mode' => $mode));
		assert_throws('VaultError', function () use ($conf) { VaultConfig::fromConf($conf); }, 'AUTH_MODE');
	}
	assert_throws('VaultError', function () { VaultConfig::fromConf(array()); }, 'AUTH_MODE');
}

function test_config_requires_admin_group() {
	foreach (array(null, '', '  ') as $group) {
		$conf = auth_conf(array('admin_group' => $group));
		assert_throws('VaultError', function () use ($conf) { VaultConfig::fromConf($conf); }, 'AUTH_ADMIN_GROUP');
	}
}

function test_config_sso_requires_proxies() {
	foreach (array(null, '', ' , ', '10.0.0.0/33', '10.0.0.5/32 garbage', array('::1/129')) as $proxies) {
		$conf = auth_conf(array('trusted_proxies' => $proxies));
		assert_throws('VaultError', function () use ($conf) { VaultConfig::fromConf($conf); }, 'AUTH_TRUSTED_PROXIES');
	}
	// Local mode doesn't use them.
	$cfg = VaultConfig::fromConf(auth_conf(array('auth_mode' => 'local', 'trusted_proxies' => '')));
	assert_same('local', $cfg['auth_mode']);
}

function test_config_requires_db_path() {
	$conf = auth_conf(array('db_path' => ''));
	assert_throws('VaultError', function () use ($conf) { VaultConfig::fromConf($conf); }, 'VAULT_DB_PATH');
}

function test_config_normalises() {
	$cfg = VaultConfig::fromConf(auth_conf(array(
		'auth_mode' => ' SSO ',
		'admin_group' => ' role-admin ',
		'trusted_proxies' => '10.0.0.5/32, 192.0.2.0/24 ::1',
		'servers_allow_ui' => 'false',
		'idle_minutes' => '15',
		'ui_defaults' => array('pg_dump_path' => '/usr/bin/pg_dump'),
	)));
	assert_same('sso', $cfg['auth_mode']);
	assert_same('role-admin', $cfg['admin_group']);
	assert_same(array('10.0.0.5/32', '192.0.2.0/24', '::1'), $cfg['trusted_proxies']);
	assert_same('Remote-User', $cfg['user_header']);
	assert_same('Remote-Groups', $cfg['groups_header']);
	assert_same(false, $cfg['servers_allow_ui']);
	assert_same(15, $cfg['idle_minutes']);
	assert_same('', $cfg['signout_url']);
	assert_same(array('pg_dump_path' => '/usr/bin/pg_dump'), $cfg['ui_defaults']);

	$cfg = VaultConfig::fromConf(auth_conf(array()));
	assert_same(true, $cfg['servers_allow_ui']);
	assert_same(30, $cfg['idle_minutes']);
	assert_same(array(), $cfg['ui_defaults']);
}

function test_app_name() {
	require_once('./classes/vault/Vault.php');
	assert_same('phppgadmin:alice', Vault::appName('alice'));
	assert_same('phppgadmin', Vault::appName(''));
	assert_same('phppgadmin:j??rg', Vault::appName("j\xc3\xb6rg"));
	assert_same(63, strlen(Vault::appName(str_repeat('a', 100))));
}

function test_audit_writes_row() {
	require_once('./classes/vault/VaultAudit.php');
	$db = VaultStore::open(unit_tmp() . '/v.sqlite');
	$audit = new VaultAudit($db);
	$_SERVER['REMOTE_ADDR'] = '10.0.0.7';
	$audit->log('alice', VaultAudit::LOGIN_USED, array('credential_id' => 'c1', 'server_id' => 'reporting-replica',
		'database' => 'app', 'detail' => array('reason' => 'x/y')));
	$audit->log('bob', VaultAudit::SIGNIN_FAILED);
	unset($_SERVER['REMOTE_ADDR']);
	$rows = $db->query('SELECT actor, action, credential_id, server_id, "database", client_ip, detail FROM audit_log ORDER BY id')->fetchAll();
	assert_same(array('actor' => 'alice', 'action' => 'login_used', 'credential_id' => 'c1', 'server_id' => 'reporting-replica',
		'database' => 'app', 'client_ip' => '10.0.0.7', 'detail' => '{"reason":"x/y"}'), $rows[0]);
	assert_same('signin_failed', $rows[1]['action']);
	assert_same(null, $rows[1]['credential_id']);
	assert_same('{}', $rows[1]['detail']);
}

function test_users_seen_and_disabled() {
	require_once('./classes/vault/VaultUsers.php');
	$db = VaultStore::open(unit_tmp() . '/v.sqlite');
	$users = new VaultUsers($db, new VaultAudit($db));
	assert_same(false, $users->isDisabled('alice'), 'unknown user');
	$users->seen('alice');
	$first = $db->query("SELECT last_seen_at, created_at FROM users WHERE username = 'alice'")->fetch();
	assert_true($first['last_seen_at'] !== null && $first['created_at'] !== null, 'row added');

	// Recent: left alone. Older than 5 minutes: updated.
	$minuteAgo = gmdate('Y-m-d\TH:i:s\Z', time() - 60);
	$db->exec("UPDATE users SET last_seen_at = '$minuteAgo'");
	$users->seen('alice');
	$recent = $db->query("SELECT last_seen_at FROM users WHERE username = 'alice'")->fetchColumn();
	assert_same($minuteAgo, $recent, 'not rewritten within 5 minutes');
	$db->exec("UPDATE users SET last_seen_at = '2000-01-01T00:00:00Z'");
	$users->seen('alice');
	assert_true($db->query("SELECT last_seen_at FROM users WHERE username = 'alice'")->fetchColumn() > '2000-01-01T00:00:00Z', 'rewritten');

	$db->exec("UPDATE users SET disabled = 1 WHERE username = 'alice'");
	assert_same(true, $users->isDisabled('alice'));
}

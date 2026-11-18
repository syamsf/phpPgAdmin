<?php

require_once('./classes/vault/VaultStore.php');
require_once('./classes/vault/VaultAudit.php');
require_once('./classes/vault/VaultServers.php');

const SRV_T0 = '2026-01-01T00:00:00Z';
const SRV_T1 = '2026-01-02T00:00:00Z';

function servers_db() {
	return VaultStore::open(unit_tmp() . '/v.sqlite');
}

function servers_for($db) {
	return new VaultServers($db, new VaultAudit($db));
}

function servers_env(string $desc, string $host = 'db', int $port = 5432) {
	return array('desc' => $desc, 'host' => $host, 'port' => $port, 'sslmode' => 'prefer', 'defaultdb' => 'postgres');
}

function servers_credential($db, string $serverKey) {
	$db->prepare('INSERT INTO credentials (id, kind, owner, label, server_id, "database", pg_username, password_enc, nonce, key_version, access_label, created_at, updated_at)
		VALUES (:id, \'shared\', \'alice\', \'l\', :s, \'postgres\', \'u\', :b, :b, 1, \'read-only\', :t, :t)')
		->execute(array(':id' => 'c-' . $serverKey, ':s' => $serverKey, ':b' => 'x', ':t' => SRV_T0));
}

function servers_row($db, string $key) {
	$stmt = $db->prepare('SELECT * FROM servers WHERE "key" = :k');
	$stmt->execute(array(':k' => $key));
	$row = $stmt->fetch(PDO::FETCH_ASSOC);
	return $row === false ? null : $row;
}

function test_slug() {
	assert_same('reporting-replica', VaultServers::slug('Reporting Replica'));
	assert_same('a-b', VaultServers::slug('--A__b--'));
	assert_same('server', VaultServers::slug(''));
}

function test_env_keys_collide() {
	assert_same(array(0 => 'main', 1 => 'main-2'),
		VaultServers::envKeys(array(servers_env('Main'), servers_env('Main', 'other'))));
}

function test_sync_inserts_env() {
	$db = servers_db();
	servers_for($db)->syncEnv(array(servers_env('Main', 'pg.example', 5433)), SRV_T0);
	$row = servers_row($db, 'main');
	assert_same('env', $row['source']);
	assert_same('Main', $row['name']);
	assert_same('pg.example', $row['host']);
	assert_same(5433, (int)$row['port']);
	assert_same('prefer', $row['sslmode']);
	assert_same('postgres', $row['default_db']);
	assert_same('active', $row['status']);
	assert_same(null, $row['created_by']);
}

function test_sync_removed_then_back() {
	$db = servers_db();
	$s = servers_for($db);
	$a = servers_env('A');
	$b = servers_env('B', 'other');
	$s->syncEnv(array($a, $b), SRV_T0);
	servers_credential($db, 'b');
	$s->syncEnv(array($a), SRV_T1);
	assert_same('removed', servers_row($db, 'b')['status']);
	assert_same('1', (string)$db->query('SELECT COUNT(*) FROM credentials WHERE server_id = \'b\'')->fetchColumn());
	$s->syncEnv(array($a, $b), SRV_T1);
	assert_same('active', servers_row($db, 'b')['status']);
}

function test_sync_rename_orphans_not_deletes() {
	$db = servers_db();
	$s = servers_for($db);
	$s->syncEnv(array(servers_env('Old')), SRV_T0);
	servers_credential($db, 'old');
	$s->syncEnv(array(servers_env('New')), SRV_T1);
	assert_same('removed', servers_row($db, 'old')['status']);
	assert_same('active', servers_row($db, 'new')['status']);
	assert_same('1', (string)$db->query('SELECT COUNT(*) FROM credentials WHERE server_id = \'old\'')->fetchColumn());
}

function test_env_takes_over_ui_key() {
	$db = servers_db();
	$db->exec("INSERT INTO servers (\"key\", name, source, host, port, sslmode, default_db, status, created_by, created_at, updated_at)
		VALUES ('main', 'Main', 'ui', 'ui-host', 5432, '', 'app', 'disabled', 'bob', '" . SRV_T0 . "', '" . SRV_T0 . "')");
	servers_credential($db, 'main');
	servers_for($db)->syncEnv(array(servers_env('Main', 'env-host')), SRV_T1);
	$row = servers_row($db, 'main');
	assert_same('env', $row['source']);
	assert_same('env-host', $row['host']);
	assert_same('active', $row['status']);
	assert_same('1', (string)$db->query('SELECT COUNT(*) FROM credentials WHERE server_id = \'main\'')->fetchColumn());
	$audit = $db->query("SELECT actor, server_id, detail FROM audit_log WHERE action = 'server_changed'")->fetchAll(PDO::FETCH_ASSOC);
	assert_same(array(array('actor' => 'system', 'server_id' => 'main', 'detail' => '{"reason":"env took over key"}')), $audit);
}

function test_conf_servers_appends_active_ui_only() {
	$db = servers_db();
	$s = servers_for($db);
	$env = array(servers_env('Main'));
	$s->syncEnv($env, SRV_T0);
	$ins = "INSERT INTO servers (\"key\", name, source, host, port, sslmode, default_db, status, created_at, updated_at)
		VALUES (:k, :n, 'ui', 'h', 6432, '', 'app', :st, '" . SRV_T0 . "', '" . SRV_T0 . "')";
	$db->prepare($ins)->execute(array(':k' => 'live', ':n' => 'Live', ':st' => 'active'));
	$db->prepare($ins)->execute(array(':k' => 'off', ':n' => 'Off', ':st' => 'disabled'));
	$out = $s->confServers($env, array('theme' => 'x'));
	assert_same(2, count($out));
	assert_same('main', $out[0]['key']);
	assert_same('env', $out[0]['source']);
	assert_same(array('desc' => 'Live', 'host' => 'h', 'port' => 6432, 'sslmode' => 'prefer', 'defaultdb' => 'app',
		'pgbouncer' => false, 'key' => 'live', 'source' => 'ui', 'theme' => 'x'), $out[1]);
}

function test_sync_mirrors_the_pgbouncer_flag() {
	$db = servers_db();
	$s = servers_for($db);
	$env = array(servers_env('Obs', 'pgb', 6432) + array('pgbouncer' => true));
	$s->syncEnv($env, SRV_T0);
	assert_same('1', (string)servers_row($db, 'obs')['pgbouncer']);
	// The env entry keeps its flag in $conf['servers'] as given.
	assert_same(true, $s->confServers($env, array())[0]['pgbouncer']);
	unset($env[0]['pgbouncer']);
	$s->syncEnv($env, SRV_T1);
	$row = servers_row($db, 'obs');
	assert_same('0', (string)$row['pgbouncer']);
	assert_same(SRV_T1, $row['updated_at']);
}

function test_conf_servers_without_ui_when_not_allowed() {
	// SERVERS_ALLOW_UI=false turns UI servers off: they leave $conf['servers'].
	$db = servers_db();
	$s = servers_for($db);
	$env = array(servers_env('Main'));
	$s->syncEnv($env, SRV_T0);
	$db->exec("INSERT INTO servers (\"key\", name, source, host, port, sslmode, default_db, status, created_at, updated_at)
		VALUES ('live', 'Live', 'ui', 'h', 6432, 'require', 'app', 'active', '" . SRV_T0 . "', '" . SRV_T0 . "')");
	$out = $s->confServers($env, array(), false);
	assert_same(array(0), array_keys($out));
	assert_same('main', $out[0]['key']);
	assert_same(2, count($s->confServers($env, array(), true)));
	// The row itself is untouched: it comes back when UI servers are allowed again.
	assert_same('active', servers_row($db, 'live')['status']);
}

function test_conf_servers_keeps_env_indexes() {
	$db = servers_db();
	$s = servers_for($db);
	$env = array(0 => servers_env('A'), 3 => servers_env('B', 'o'));
	$s->syncEnv($env, SRV_T0);
	$db->exec("INSERT INTO servers (\"key\", name, source, host, port, sslmode, default_db, status, created_at, updated_at)
		VALUES ('ui1', 'U', 'ui', 'h', 5432, 'require', 'd', 'active', '" . SRV_T0 . "', '" . SRV_T0 . "')");
	$out = $s->confServers($env, array());
	assert_same(array(0, 3, 4), array_keys($out));
	assert_same('require', $out[4]['sslmode']);
}

function test_sync_writes_nothing_when_unchanged() {
	$db = servers_db();
	$s = servers_for($db);
	$env = array(servers_env('Main'));
	$s->syncEnv($env, SRV_T0);
	$s->syncEnv($env, SRV_T1);
	assert_same(SRV_T0, servers_row($db, 'main')['updated_at']);
	assert_same(SRV_T0, servers_row($db, 'main')['created_at']);
}

function test_get() {
	$db = servers_db();
	$s = servers_for($db);
	$s->syncEnv(array(servers_env('Main')), SRV_T0);
	assert_same('Main', $s->get('main')['name']);
	assert_same(null, $s->get('nope'));
}

function test_sync_from_second_connection_after_first() {
	$path = unit_tmp() . '/v.sqlite';
	$one = VaultStore::open($path);
	$two = VaultStore::open($path);
	$env = array(servers_env('Main'));
	// $two reads first (its snapshot is stale once $one writes), then both sync.
	$two->query('SELECT COUNT(*) FROM servers')->fetchAll();
	servers_for($one)->syncEnv($env, SRV_T0);
	servers_for($two)->syncEnv($env, SRV_T1);
	assert_same(SRV_T0, servers_row($one, 'main')['updated_at']);
	assert_same('1', (string)$one->query('SELECT COUNT(*) FROM servers')->fetchColumn());
}

function servers_form(array $over = array()) {
	return $over + array('key' => 'extra', 'name' => 'Extra', 'host' => 'h.example', 'port' => '5432',
		'sslmode' => 'require', 'default_db' => 'app', 'enabled' => true);
}

function servers_audit($db, string $action) {
	return $db->query("SELECT actor, credential_id, server_id, detail FROM audit_log WHERE action = '$action' ORDER BY id")->fetchAll(PDO::FETCH_ASSOC);
}

function test_pgbouncer_flag_on_ui_servers() {
	$db = servers_db();
	$s = servers_for($db);
	$s->add(servers_form(array('pgbouncer' => '1')), 'boss');
	assert_same('1', (string)servers_row($db, 'extra')['pgbouncer']);
	assert_same(true, $s->confServers(array(), array())[0]['pgbouncer']);
	assert_same(true, json_decode(servers_audit($db, 'server_added')[0]['detail'], true)['pgbouncer']);
	// It doesn't move the server: it can change while the server holds logins.
	servers_credential($db, 'extra');
	$s->update('extra', servers_form(), 'boss');
	assert_same('0', (string)servers_row($db, 'extra')['pgbouncer']);
	assert_same(false, $s->confServers(array(), array())[0]['pgbouncer']);
	$changed = json_decode(servers_audit($db, 'server_changed')[0]['detail'], true)['changed'];
	assert_same(array('pgbouncer'), array_keys($changed));
}

function test_add_inserts_ui_row_and_audits() {
	$db = servers_db();
	$s = servers_for($db);
	$s->add(servers_form(), 'boss');
	$row = servers_row($db, 'extra');
	assert_same('ui', $row['source']);
	assert_same('active', $row['status']);
	assert_same('boss', $row['created_by']);
	assert_same(5432, (int)$row['port']);
	assert_same('require', $row['sslmode']);
	$rows = servers_audit($db, 'server_added');
	assert_same(1, count($rows));
	assert_same('extra', $rows[0]['server_id']);
	$s->add(servers_form(array('key' => 'off', 'host' => 'o.example', 'enabled' => false)), 'boss');
	assert_same('disabled', servers_row($db, 'off')['status']);
}

function test_add_rejects_bad_fields() {
	$s = servers_for(servers_db());
	foreach (array(
		array('key' => 'Bad Key', 'strvaultbadserverkey'),
		array('key' => '-x', 'strvaultbadserverkey'),
		array('name' => '', 'strvaultbadservername'),
		array('name' => str_repeat('n', 101), 'strvaultbadservername'),
		array('host' => 'a b', 'strvaultbadhost'),
		array('host' => '', 'strvaultbadhost'),
		array('port' => '0', 'strvaultbadport'),
		array('port' => '65536', 'strvaultbadport'),
		array('port' => 'x', 'strvaultbadport'),
		array('sslmode' => 'allow', 'strvaultbadsslmode'),
		array('default_db' => '', 'strvaultbaddatabase'),
		array('default_db' => str_repeat('d', 64), 'strvaultbaddatabase'),
	) as $case) {
		$msg = $case[0];
		unset($case[0]);
		assert_throws('VaultError', function () use ($s, $case) {
			$s->add(servers_form($case), 'boss');
		}, $msg);
	}
}

function test_add_rejects_used_key() {
	$db = servers_db();
	$s = servers_for($db);
	$s->syncEnv(array(servers_env('Main')), SRV_T0);
	assert_throws('VaultError', function () use ($s) {
		$s->add(servers_form(array('key' => 'main')), 'boss');
	}, 'strvaultserverkeytaken');
	$s->add(servers_form(), 'boss');
	assert_throws('VaultError', function () use ($s) {
		$s->add(servers_form(array('host' => 'other')), 'boss');
	}, 'strvaultserverkeytaken');
}

function test_add_rejects_same_host_port_sslmode_and_names_it() {
	$db = servers_db();
	$s = servers_for($db);
	$env = servers_env('Tls', 'db');
	$env['sslmode'] = 'require';
	$s->syncEnv(array($env), SRV_T0);
	assert_throws('VaultError', function () use ($s) {
		$s->add(servers_form(array('host' => 'DB')), 'boss');
	}, 'Tls');
	$s->add(servers_form(array('host' => 'db', 'sslmode' => 'disable')), 'boss');
	assert_same(1, count(servers_audit($db, 'server_added')));
}

function test_disabled_server_does_not_block_a_duplicate() {
	$db = servers_db();
	$s = servers_for($db);
	$s->add(servers_form(array('enabled' => false)), 'boss');
	$s->add(servers_form(array('key' => 'second', 'name' => 'Second')), 'boss');
	assert_throws('VaultError', function () use ($s) {
		$s->setStatus('extra', 'active', 'boss');
	}, 'Second');
}

function test_update_changes_and_audits_fields() {
	$db = servers_db();
	$s = servers_for($db);
	$s->add(servers_form(), 'boss');
	$s->update('extra', servers_form(array('name' => 'Renamed', 'port' => '6432', 'key' => 'ignored')), 'boss2');
	$row = servers_row($db, 'extra');
	assert_same('Renamed', $row['name']);
	assert_same(6432, (int)$row['port']);
	assert_same(null, servers_row($db, 'ignored'));
	$rows = servers_audit($db, 'server_changed');
	assert_same(1, count($rows));
	assert_same('boss2', $rows[0]['actor']);
	$detail = json_decode($rows[0]['detail'], true);
	assert_same(array('name', 'port'), array_keys($detail['changed']));
	assert_same('Extra', $detail['changed']['name']['from']);
	// Saving the same values writes and audits nothing.
	$s->update('extra', servers_form(array('name' => 'Renamed', 'port' => '6432')), 'boss2');
	assert_same(1, count(servers_audit($db, 'server_changed')));
}

function test_update_with_logins_keeps_the_target() {
	// Saved passwords would go to the new host: host, port and a weaker SSL
	// mode are refused while the server holds logins.
	$db = servers_db();
	$s = servers_for($db);
	$s->add(servers_form(array('sslmode' => 'require')), 'boss');
	servers_credential($db, 'extra');
	foreach (array(array('host' => 'evil.example'), array('port' => '6432'), array('sslmode' => 'prefer'),
			array('sslmode' => 'disable')) as $over) {
		assert_throws('VaultError', function () use ($s, $over) {
			$s->update('extra', servers_form($over + array('sslmode' => 'require')), 'boss');
		}, 'strvaultserverhaslogins');
	}
	$row = servers_row($db, 'extra');
	assert_same(array('h.example', 5432, 'require'), array($row['host'], (int)$row['port'], $row['sslmode']));
	assert_same(0, count(servers_audit($db, 'server_changed')));
	// A stricter SSL mode, a new name or default database, or the host in
	// other letter case, are fine.
	$s->update('extra', servers_form(array('sslmode' => 'verify-full', 'name' => 'Renamed', 'default_db' => 'other',
		'host' => 'H.Example')), 'boss');
	$row = servers_row($db, 'extra');
	assert_same(array('verify-full', 'Renamed', 'other'), array($row['sslmode'], $row['name'], $row['default_db']));
	assert_throws('VaultError', function () use ($s) {
		$s->update('extra', servers_form(array('sslmode' => 'require')), 'boss');
	}, 'strvaultserverhaslogins');
	// A personal login counts too; without any login everything may change.
	$db->exec('DELETE FROM credentials');
	$db->exec("INSERT INTO credentials (id, kind, owner, label, server_id, \"database\", pg_username, password_enc, nonce, key_version, access_label, created_at, updated_at)
		VALUES ('p1', 'personal', 'carol', 'l', 'extra', 'app', 'u', 'x', 'x', 1, 'read-write', '" . SRV_T0 . "', '" . SRV_T0 . "')");
	assert_throws('VaultError', function () use ($s) {
		$s->update('extra', servers_form(array('host' => 'evil.example', 'sslmode' => 'verify-full')), 'boss');
	}, 'strvaultserverhaslogins');
	$db->exec('DELETE FROM credentials');
	$s->update('extra', servers_form(array('host' => 'new.example', 'port' => '6432', 'sslmode' => 'disable')), 'boss');
	$row = servers_row($db, 'extra');
	assert_same(array('new.example', 6432, 'disable'), array($row['host'], (int)$row['port'], $row['sslmode']));
}

function test_update_ignores_itself_in_duplicate_check() {
	$s = servers_for(servers_db());
	$s->add(servers_form(), 'boss');
	$s->update('extra', servers_form(array('name' => 'Same host')), 'boss');
	$s->add(servers_form(array('key' => 'other', 'host' => 'o.example')), 'boss');
	assert_throws('VaultError', function () use ($s) {
		$s->update('other', servers_form(array('host' => 'h.example')), 'boss');
	}, 'Same host');
}

function test_env_rows_refuse_writes() {
	$db = servers_db();
	$s = servers_for($db);
	$s->syncEnv(array(servers_env('Main')), SRV_T0);
	assert_throws('VaultError', function () use ($s) { $s->update('main', servers_form(), 'boss'); }, 'strvaultenvreadonly');
	assert_throws('VaultError', function () use ($s) { $s->setStatus('main', 'disabled', 'boss'); }, 'strvaultenvreadonly');
	assert_throws('VaultError', function () use ($s) { $s->delete('main', 'boss'); }, 'strvaultenvreadonly');
	assert_same('Main', servers_row($db, 'main')['name']);
	assert_same('active', servers_row($db, 'main')['status']);
	assert_same(0, count(servers_audit($db, 'server_changed')));
	// A removed env row can't be edited or enabled either.
	$s->syncEnv(array(), SRV_T1);
	assert_throws('VaultError', function () use ($s) { $s->setStatus('main', 'active', 'boss'); }, 'strvaultenvreadonly');
	assert_throws('VaultError', function () use ($s) { $s->update('missing', servers_form(), 'boss'); }, 'strvaultservernotfound');
}

function test_set_status_toggles_and_audits() {
	$db = servers_db();
	$s = servers_for($db);
	$s->add(servers_form(), 'boss');
	$s->setStatus('extra', 'disabled', 'boss');
	assert_same('disabled', servers_row($db, 'extra')['status']);
	$s->setStatus('extra', 'active', 'boss');
	assert_same('active', servers_row($db, 'extra')['status']);
	assert_same(2, count(servers_audit($db, 'server_changed')));
	assert_throws('VaultError', function () use ($s) { $s->setStatus('extra', 'removed', 'boss'); }, 'strvaultbadserverstatus');
}

function test_delete_cascades_and_audits_each_login() {
	$db = servers_db();
	$s = servers_for($db);
	$s->add(servers_form(), 'boss');
	$s->add(servers_form(array('key' => 'keep', 'host' => 'k.example')), 'boss');
	servers_credential($db, 'extra');
	servers_credential($db, 'keep');
	$db->exec("INSERT INTO credentials (id, kind, owner, label, server_id, \"database\", pg_username, password_enc, nonce, key_version, access_label, created_at, updated_at)
		VALUES ('p1', 'personal', 'carol', 'secret label', 'extra', 'app', 'u', 'x', 'x', 1, 'read-write', '" . SRV_T0 . "', '" . SRV_T0 . "')");
	$counts = $s->delete('extra', 'boss');
	assert_same(array('personal' => 1, 'shared' => 1), $counts);
	assert_same(null, servers_row($db, 'extra'));
	assert_same('0', (string)$db->query("SELECT COUNT(*) FROM credentials WHERE server_id = 'extra'")->fetchColumn());
	assert_same('1', (string)$db->query("SELECT COUNT(*) FROM credentials WHERE server_id = 'keep'")->fetchColumn());
	$rows = servers_audit($db, 'credential_deleted');
	assert_same(2, count($rows));
	assert_same('{"reason":"server_deleted"}', $rows[0]['detail']);
	$ids = array_column($rows, 'credential_id');
	sort($ids);
	assert_same(array('c-extra', 'p1'), $ids);
	assert_same(1, count(servers_audit($db, 'server_deleted')));
}

function test_delete_removed_env_row() {
	$db = servers_db();
	$s = servers_for($db);
	$s->syncEnv(array(servers_env('Main'), servers_env('Gone', 'g')), SRV_T0);
	servers_credential($db, 'gone');
	$s->syncEnv(array(servers_env('Main')), SRV_T1);
	assert_same(array('personal' => 0, 'shared' => 1), $s->delete('gone', 'boss'));
	assert_same(null, servers_row($db, 'gone'));
	assert_same('0', (string)$db->query('SELECT COUNT(*) FROM credentials')->fetchColumn());
}

function test_delete_is_all_or_nothing() {
	$db = servers_db();
	$s = servers_for($db);
	$s->add(servers_form(), 'boss');
	servers_credential($db, 'extra');
	$db->exec('CREATE TRIGGER fail_srv BEFORE DELETE ON servers BEGIN SELECT RAISE(ABORT, \'no\'); END');
	assert_throws('PDOException', function () use ($s) { $s->delete('extra', 'boss'); });
	assert_same(0, count(servers_audit($db, 'credential_deleted')));
	assert_same('1', (string)$db->query('SELECT COUNT(*) FROM credentials')->fetchColumn());
	assert_same(false, $db->inTransaction());
}

function test_list_with_counts_orders_env_first() {
	$db = servers_db();
	$s = servers_for($db);
	$s->syncEnv(array(servers_env('Zed'), servers_env('Alpha', 'a')), SRV_T0);
	$s->add(servers_form(array('key' => 'aaa')), 'boss');
	servers_credential($db, 'zed');
	$db->exec("INSERT INTO credentials (id, kind, owner, label, server_id, \"database\", pg_username, password_enc, nonce, key_version, access_label, created_at, updated_at)
		VALUES ('p1', 'personal', 'carol', 'l', 'zed', 'app', 'u', 'x', 'x', 1, 'read-write', '" . SRV_T0 . "', '" . SRV_T0 . "')");
	$rows = $s->listWithCounts();
	assert_same(array('alpha', 'zed', 'aaa'), array_column($rows, 'key'));
	assert_same(array(1, 1), array((int)$rows[1]['personal_count'], (int)$rows[1]['shared_count']));
	assert_same(array(0, 0), array((int)$rows[0]['personal_count'], (int)$rows[0]['shared_count']));
}

function test_impact_counts_owners_and_principals() {
	$db = servers_db();
	$s = servers_for($db);
	$s->add(servers_form(), 'boss');
	servers_credential($db, 'extra');
	$db->exec("INSERT INTO credential_shares (credential_id, principal_type, principal, expires_at, granted_by, granted_at)
		VALUES ('c-extra', 'group', 'dba', NULL, 'boss', '" . SRV_T0 . "'), ('c-extra', 'user', 'dan', NULL, 'boss', '" . SRV_T0 . "')");
	foreach (array('p1' => 'carol', 'p2' => 'carol', 'p3' => 'erin') as $id => $owner) {
		$db->exec("INSERT INTO credentials (id, kind, owner, label, server_id, \"database\", pg_username, password_enc, nonce, key_version, access_label, created_at, updated_at)
			VALUES ('$id', 'personal', '$owner', '$id', 'extra', 'app', 'u', 'x', 'x', 1, 'read-write', '" . SRV_T0 . "', '" . SRV_T0 . "')");
	}
	assert_same(array('personal' => 3, 'owners' => 2, 'shared' => 1, 'principals' => array(array('group', 'dba'), array('user', 'dan'))),
		$s->impact('extra'));
}

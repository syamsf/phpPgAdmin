<?php

require_once('./classes/vault/VaultStore.php');
require_once('./classes/vault/VaultCrypto.php');
require_once('./classes/vault/VaultAudit.php');
require_once('./classes/vault/VaultIdentity.php');
require_once('./classes/vault/VaultCredentials.php');
require_once('./classes/vault/VaultFormat.php');

const CRD_NOW = '2026-06-10T12:00:00Z';
const CRD_NOW_TS = 1781092800; // 2026-06-10T12:00:00Z

function creds_fixture() {
	$db = VaultStore::open(unit_tmp() . '/v.sqlite');
	foreach (array('s1', 's2') as $k) {
		$db->prepare('INSERT INTO servers ("key", name, source, host, port, sslmode, default_db, status, created_at, updated_at)
			VALUES (:k, :k, \'ui\', \'db.example.internal\', 5432, \'\', \'postgres\', \'active\', :t, :t)')
			->execute(array(':k' => $k, ':t' => CRD_NOW));
	}
	$crypto = new VaultCrypto(array(1 => str_repeat('k', 32)), 1);
	$audit = new VaultAudit($db);
	return array(
		'db' => $db, 'crypto' => $crypto, 'audit' => $audit,
		'creds' => new VaultCredentials($db, $crypto, $audit),
		'alice' => new VaultIdentity('alice', array('dba'), 'role-admin', 'sso'),
		'bob' => new VaultIdentity('bob', array('finance'), 'role-admin', 'sso'),
		'boss' => new VaultIdentity('boss', array('role-admin'), 'role-admin', 'sso'),
	);
}

/** A shared credential inserted by SQL (share() comes later). */
function make_shared($db, $crypto, string $label, string $server = 's1', string $database = 'db1', string $password = 'shared-pw') {
	$id = VaultStore::uuid();
	list($c, $n, $v) = $crypto->encrypt($password, VaultCrypto::aad($id, $server, 'app'));
	$stmt = $db->prepare('INSERT INTO credentials (id, kind, owner, label, server_id, "database", pg_username, password_enc, nonce, key_version, access_label, created_at, updated_at)
		VALUES (:id, \'shared\', \'boss\', :l, :s, :d, \'app\', :c, :n, :v, \'read-only\', :t, :t)');
	$stmt->bindValue(':id', $id);
	$stmt->bindValue(':l', $label);
	$stmt->bindValue(':s', $server);
	$stmt->bindValue(':d', $database);
	$stmt->bindValue(':c', $c, PDO::PARAM_LOB);
	$stmt->bindValue(':n', $n, PDO::PARAM_LOB);
	$stmt->bindValue(':v', $v);
	$stmt->bindValue(':t', CRD_NOW);
	$stmt->execute();
	return $id;
}

function make_share($db, string $id, string $type, string $principal, ?string $expires = null) {
	$db->prepare('INSERT INTO credential_shares (credential_id, principal_type, principal, expires_at, granted_by, granted_at)
		VALUES (:id, :t, :p, :e, \'boss\', :now)')
		->execute(array(':id' => $id, ':t' => $type, ':p' => $principal, ':e' => $expires, ':now' => CRD_NOW));
}

function test_personal_visible_only_to_owner() {
	$f = creds_fixture();
	$id = $f['creds']->savePersonal($f['alice'], 's1', 'db1', 'alice_pg', 'pw1', 'My login');
	$rows = $f['creds']->listFor($f['alice'], 's1', 'db1', CRD_NOW);
	assert_same(1, count($rows));
	assert_same($id, $rows[0]['id']);
	assert_same('personal', $rows[0]['kind']);
	assert_same(null, $rows[0]['via']);
	assert_same(array(), $f['creds']->listFor($f['bob'], 's1', 'db1', CRD_NOW));
	assert_same(array(), $f['creds']->listFor($f['boss'], 's1', 'db1', CRD_NOW));
	assert_same(array(), $f['creds']->mine($f['boss']));
	assert_same(1, count($f['creds']->mine($f['alice'])));
}

function test_admin_cannot_use_personal() {
	$f = creds_fixture();
	$id = $f['creds']->savePersonal($f['alice'], 's1', 'db1', 'alice_pg', 'pw1', 'My login');
	assert_same(null, $f['creds']->canUse($f['boss'], $id, CRD_NOW));
	assert_same(null, $f['creds']->canUse($f['bob'], $id, CRD_NOW));
	assert_same(null, $f['creds']->get($f['boss'], $id));
	assert_true($f['creds']->canUse($f['alice'], $id, CRD_NOW) !== null);
	assert_throws('VaultError', function () use ($f, $id) { $f['creds']->delete($f['boss'], $id); }, 'strvaultnotfound');
	assert_throws('VaultError', function () use ($f, $id) { $f['creds']->updatePassword($f['boss'], $id, 'x'); }, 'strvaultnotfound');
	assert_throws('VaultError', function () use ($f, $id) { $f['creds']->rename($f['boss'], $id, 'x', 'read-only'); }, 'strvaultnotfound');
}

function test_shared_by_group_and_user() {
	$f = creds_fixture();
	$a = make_shared($f['db'], $f['crypto'], 'Reporting');
	$b = make_shared($f['db'], $f['crypto'], 'Analytics');
	make_share($f['db'], $a, 'group', 'dba');
	make_share($f['db'], $b, 'user', 'alice', '2026-07-01T00:00:00Z');
	make_share($f['db'], $b, 'group', 'dba', '2026-08-01T00:00:00Z');
	$rows = $f['creds']->listFor($f['alice'], 's1', 'db1', CRD_NOW);
	assert_same(2, count($rows));
	assert_same('Analytics', $rows[0]['label']);
	assert_same('you', $rows[0]['via']);
	assert_same('2026-08-01T00:00:00Z', $rows[0]['expires_at']);
	assert_same('Reporting', $rows[1]['label']);
	assert_same('group:dba', $rows[1]['via']);
	assert_same(null, $rows[1]['expires_at']);
	assert_same(array(), $f['creds']->listFor($f['bob'], 's1', 'db1', CRD_NOW));
	assert_same(array(), $f['creds']->listFor($f['boss'], 's1', 'db1', CRD_NOW));
	assert_true($f['creds']->canUse($f['alice'], $a, CRD_NOW) !== null);
	assert_same(null, $f['creds']->canUse($f['bob'], $a, CRD_NOW));
	assert_same(2, count($f['creds']->sharedWithMe($f['alice'], CRD_NOW)));
	// An admin may manage a shared login but not use it without a share.
	assert_same(null, $f['creds']->canUse($f['boss'], $a, CRD_NOW));
	assert_true($f['creds']->get($f['boss'], $a) !== null);
	assert_same(null, $f['creds']->get($f['alice'], $a));
}

function test_via_prefers_alphabetical_group() {
	$f = creds_fixture();
	$id = make_shared($f['db'], $f['crypto'], 'Multi');
	$who = new VaultIdentity('carol', array('zeta', 'beta'), 'role-admin', 'sso');
	make_share($f['db'], $id, 'group', 'zeta');
	make_share($f['db'], $id, 'group', 'beta');
	$rows = $f['creds']->listFor($who, 's1', 'db1', CRD_NOW);
	assert_same('group:beta', $rows[0]['via']);
}

function test_expired_share_hidden() {
	$f = creds_fixture();
	$id = make_shared($f['db'], $f['crypto'], 'Reporting');
	make_share($f['db'], $id, 'user', 'alice', '2026-06-10T11:59:59Z');
	assert_same(array(), $f['creds']->listFor($f['alice'], 's1', 'db1', CRD_NOW));
	assert_same(null, $f['creds']->canUse($f['alice'], $id, CRD_NOW));
	assert_same(array(), $f['creds']->sharedWithMe($f['alice'], CRD_NOW));
}

function test_scope_by_server_and_database() {
	$f = creds_fixture();
	$f['creds']->savePersonal($f['alice'], 's1', 'db1', 'u', 'pw', 'P');
	$id = make_shared($f['db'], $f['crypto'], 'S');
	make_share($f['db'], $id, 'user', 'alice');
	assert_same(2, count($f['creds']->listFor($f['alice'], 's1', 'db1', CRD_NOW)));
	assert_same(array(), $f['creds']->listFor($f['alice'], 's1', 'db2', CRD_NOW));
	assert_same(array(), $f['creds']->listFor($f['alice'], 's2', 'db1', CRD_NOW));
}

function test_disabled_server_hides_logins() {
	$f = creds_fixture();
	$p = $f['creds']->savePersonal($f['alice'], 's1', 'db1', 'u', 'pw', 'P');
	$s = make_shared($f['db'], $f['crypto'], 'S');
	make_share($f['db'], $s, 'user', 'alice');
	$f['db']->exec('UPDATE servers SET status = \'disabled\' WHERE "key" = \'s1\'');
	assert_same(array(), $f['creds']->listFor($f['alice'], 's1', 'db1', CRD_NOW));
	assert_same(null, $f['creds']->canUse($f['alice'], $p, CRD_NOW));
	assert_same(null, $f['creds']->canUse($f['alice'], $s, CRD_NOW));
	assert_same(array(), $f['creds']->mine($f['alice']));
	assert_same(array(), $f['creds']->sharedWithMe($f['alice'], CRD_NOW));
	$f['db']->exec('UPDATE servers SET status = \'active\' WHERE "key" = \'s1\'');
	assert_same(2, count($f['creds']->listFor($f['alice'], 's1', 'db1', CRD_NOW)));
}

function test_password_roundtrip() {
	$f = creds_fixture();
	$id = $f['creds']->savePersonal($f['alice'], 's1', 'db1', 'u', 'p@ss w0rd', '  Trimmed  ', 'read-only');
	$row = $f['creds']->canUse($f['alice'], $id, CRD_NOW);
	assert_same('p@ss w0rd', $f['creds']->password($row));
	assert_same('Trimmed', $row['label']);
	assert_same('read-only', $row['access_label']);
	$s = make_shared($f['db'], $f['crypto'], 'S', 's1', 'db1', 'shared-secret');
	make_share($f['db'], $s, 'user', 'alice');
	assert_same('shared-secret', $f['creds']->password($f['creds']->canUse($f['alice'], $s, CRD_NOW)));
	$got = $f['creds']->get($f['alice'], $id);
	assert_true(!array_key_exists('password_enc', $got) && !array_key_exists('nonce', $got));
}

function test_copied_ciphertext_fails() {
	$f = creds_fixture();
	$a = $f['creds']->savePersonal($f['alice'], 's1', 'db1', 'u', 'pw-a', 'A');
	$b = $f['creds']->savePersonal($f['alice'], 's1', 'db1', 'u', 'pw-b', 'B');
	$f['db']->prepare('UPDATE credentials SET password_enc = (SELECT password_enc FROM credentials WHERE id = :a),
		nonce = (SELECT nonce FROM credentials WHERE id = :a) WHERE id = :b')
		->execute(array(':a' => $a, ':b' => $b));
	$row = $f['creds']->canUse($f['alice'], $b, CRD_NOW);
	assert_throws('VaultError', function () use ($f, $row) { $f['creds']->password($row); }, 'can\'t be decrypted');
}

function test_update_password_resets_status() {
	$f = creds_fixture();
	$id = $f['creds']->savePersonal($f['alice'], 's1', 'db1', 'u', 'old', 'A');
	$f['creds']->markFailed($id);
	assert_same('auth_failed', $f['creds']->canUse($f['alice'], $id, CRD_NOW)['last_status']);
	$f['creds']->updatePassword($f['alice'], $id, 'new');
	$row = $f['creds']->canUse($f['alice'], $id, CRD_NOW);
	assert_same('ok', $row['last_status']);
	assert_same('new', $f['creds']->password($row));
	$f['creds']->markUsed($id, CRD_NOW);
	assert_same(CRD_NOW, $f['creds']->canUse($f['alice'], $id, CRD_NOW)['last_used_at']);
	// Admin updates a shared password.
	$s = make_shared($f['db'], $f['crypto'], 'S');
	$f['creds']->updatePassword($f['boss'], $s, 'rotated');
	$f['creds']->rename($f['alice'], $id, 'Renamed', 'read-only');
	assert_same('Renamed', $f['creds']->get($f['alice'], $id)['label']);
	assert_throws('VaultError', function () use ($f, $s) { $f['creds']->rename($f['boss'], $s, 'x', 'read-only'); }, 'strvaultnotfound');
}

function test_delete_cascades_shares() {
	$f = creds_fixture();
	$s = make_shared($f['db'], $f['crypto'], 'S');
	make_share($f['db'], $s, 'user', 'alice');
	assert_throws('VaultError', function () use ($f, $s) { $f['creds']->delete($f['alice'], $s); }, 'strvaultnotfound');
	$f['creds']->delete($f['boss'], $s);
	assert_same(0, (int)$f['db']->query('SELECT COUNT(*) FROM credential_shares')->fetchColumn());
	assert_same(null, $f['creds']->canUse($f['alice'], $s, CRD_NOW));
	assert_same(1, count($f['audit']->forCredential($s, 10)));
	assert_throws('VaultError', function () use ($f, $s) { $f['creds']->delete($f['boss'], $s); }, 'strvaultnotfound');
}

function test_audit_never_holds_password() {
	$f = creds_fixture();
	$id = $f['creds']->savePersonal($f['alice'], 's1', 'db1', 'u', 'Sup3r-Secret-A', 'OldLabelX');
	$f['creds']->markUsed($id, CRD_NOW);
	$f['creds']->updatePassword($f['alice'], $id, 'Sup3r-Secret-B');
	$f['creds']->rename($f['alice'], $id, 'NewLabelY', 'read-only');
	$f['creds']->delete($f['alice'], $id);
	$all = implode("\n", $f['db']->query('SELECT detail FROM audit_log')->fetchAll(PDO::FETCH_COLUMN));
	assert_true(strpos($all, 'Sup3r-Secret') === false, 'password in audit');
	assert_true(strpos($all, 'OldLabelX') === false && strpos($all, 'NewLabelY') === false, 'personal label in audit');
	assert_true((int)$f['db']->query('SELECT COUNT(*) FROM audit_log')->fetchColumn() >= 4);
	$rows = $f['audit']->forCredential($id, 2);
	assert_same(2, count($rows));
	assert_same(VaultAudit::CREDENTIAL_DELETED, $rows[0]['action']);
}

function test_validation() {
	$f = creds_fixture();
	$c = $f['creds'];
	$a = $f['alice'];
	assert_throws('VaultError', function () use ($c, $a) { $c->savePersonal($a, 's1', 'db1', 'u', 'pw', '   '); }, 'strvaultbadlabel');
	assert_throws('VaultError', function () use ($c, $a) { $c->savePersonal($a, 's1', 'db1', 'u', 'pw', str_repeat('x', 101)); }, 'strvaultbadlabel');
	assert_throws('VaultError', function () use ($c, $a) { $c->savePersonal($a, 's1', 'db1', '', 'pw', 'L'); }, 'strvaultbadpguser');
	assert_throws('VaultError', function () use ($c, $a) { $c->savePersonal($a, 's1', 'db1', str_repeat('u', 64), 'pw', 'L'); }, 'strvaultbadpguser');
	assert_throws('VaultError', function () use ($c, $a) { $c->savePersonal($a, 's1', '', 'u', 'pw', 'L'); }, 'strvaultbaddatabase');
	assert_throws('VaultError', function () use ($c, $a) { $c->savePersonal($a, 's1', 'db1', 'u', '', 'L'); }, 'strvaultbadpassword');
	assert_throws('VaultError', function () use ($c, $a) { $c->savePersonal($a, 's1', 'db1', 'u', str_repeat('p', 1001), 'L'); }, 'strvaultbadpassword');
	assert_throws('VaultError', function () use ($c, $a) { $c->savePersonal($a, 's1', 'db1', 'u', 'pw', 'L', 'admin'); }, 'strvaultbadaccess');
	assert_throws('VaultError', function () use ($c, $a) { $c->savePersonal($a, 'nope', 'db1', 'u', 'pw', 'L'); }, 'strvaultservernotfound');
	assert_same(str_repeat('x', 100), $c->get($a, $c->savePersonal($a, 's1', 'db1', 'u', str_repeat('p', 1000), str_repeat('x', 100)))['label']);
}

function test_login_lock_window() {
	$insert = function (array $f, int $ago, string $detail) {
		$f['db']->prepare('INSERT INTO audit_log (at, actor, action, server_id, detail) VALUES (:at, \'alice\', \'login_failed\', \'s1\', :detail)')
			->execute(array(':at' => gmdate('Y-m-d\TH:i:s\Z', CRD_NOW_TS - $ago), ':detail' => $detail));
	};
	$badPassword = '{"pg_username":"u","reason":"strloginbadpassword"}';

	$f = creds_fixture();
	for ($i = 0; $i < 4; $i++) {
		$insert($f, 10, $badPassword);
	}
	assert_same(0, $f['audit']->loginLockSeconds('alice', 's1', CRD_NOW_TS));
	$insert($f, 100, $badPassword);
	assert_same(200, $f['audit']->loginLockSeconds('alice', 's1', CRD_NOW_TS));
	assert_same(0, $f['audit']->loginLockSeconds('bob', 's1', CRD_NOW_TS));
	assert_same(0, $f['audit']->loginLockSeconds('alice', 's2', CRD_NOW_TS));
	assert_same(0, $f['audit']->loginLockSeconds('alice', 's1', CRD_NOW_TS + 400));

	$g = creds_fixture();
	for ($i = 0; $i < 5; $i++) {
		$insert($g, 301, $badPassword);
	}
	assert_same(0, $g['audit']->loginLockSeconds('alice', 's1', CRD_NOW_TS));

	// Only wrong passwords count: a missing database, an unreachable host
	// or no reason at all is not password guessing.
	$h = creds_fixture();
	foreach (array('strloginnodb', 'strloginunreachable', 'strloginhba', '', 'strloginnodb') as $reason) {
		$insert($h, 10, json_encode(array('pg_username' => 'u', 'reason' => $reason)));
	}
	$insert($h, 10, '{}');
	assert_same(0, $h['audit']->loginLockSeconds('alice', 's1', CRD_NOW_TS));
	for ($i = 0; $i < 4; $i++) {
		$insert($h, 20, $badPassword);
	}
	assert_same(0, $h['audit']->loginLockSeconds('alice', 's1', CRD_NOW_TS));
}

function test_ago() {
	global $lang;
	require './lang/english.php';
	$n = CRD_NOW_TS;
	$at = function (int $secs) { return gmdate('Y-m-d\TH:i:s\Z', $secs); };
	assert_same('never', VaultFormat::ago(null, $n));
	assert_same('just now', VaultFormat::ago($at($n - 30), $n));
	assert_same('5 minutes ago', VaultFormat::ago($at($n - 300), $n));
	assert_same('today', VaultFormat::ago($at($n - 7200), $n)); // 10:00 same day
	assert_same('yesterday', VaultFormat::ago($at($n - 86400), $n));
	assert_same('3 days ago', VaultFormat::ago($at($n - 3 * 86400), $n));
	// Calendar days, not elapsed 24h periods: 8 Jun 23:50 seen at 10 Jun 00:30.
	assert_same('2 days ago', VaultFormat::ago('2026-06-08T23:50:00Z', gmdate('U', 0) + strtotime('2026-06-10T00:30:00Z')));
	assert_same('3 weeks ago', VaultFormat::ago($at($n - 21 * 86400), $n));
	assert_same('1 Jan 2026', VaultFormat::ago('2026-01-01T08:00:00Z', $n));
	assert_same('1 Jan 2026', VaultFormat::date('2026-01-01T08:00:00Z'));
}

// --- Sharing (Task 10)

function share_today_offset(int $days): string {
	return gmdate('Y-m-d', time() + $days * 86400);
}

function test_share_and_unshare() {
	$f = creds_fixture();
	$id = make_shared($f['db'], $f['crypto'], 'Reporting');
	$f['creds']->share($f['boss'], $id, 'group', '  dba ', null);
	$rows = $f['creds']->shares($id);
	assert_same(1, count($rows));
	assert_same('group', $rows[0]['principal_type']);
	assert_same('dba', $rows[0]['principal'], 'the principal is trimmed');
	assert_same(null, $rows[0]['expires_at']);
	assert_same('boss', $rows[0]['granted_by']);
	assert_true($f['creds']->canUse($f['alice'], $id, CRD_NOW) !== null, 'alice (dba) can use it');

	// Sharing again replaces the row: one row, the new expiry.
	$date = share_today_offset(30);
	$f['creds']->share($f['boss'], $id, 'group', 'dba', $date);
	$f['creds']->share($f['boss'], $id, 'user', 'bob', null);
	$rows = $f['creds']->shares($id);
	assert_same(2, count($rows));
	assert_same('group', $rows[0]['principal_type'], 'groups first');
	assert_same($date . 'T23:59:59Z', $rows[0]['expires_at']);
	assert_same('bob', $rows[1]['principal']);

	$audit = $f['audit']->forCredential($id, 10);
	assert_same(VaultAudit::SHARE_ADDED, $audit[0]['action']);
	assert_same(array('type' => 'user', 'principal' => 'bob', 'expires_at' => null), json_decode($audit[0]['detail'], true));
	assert_same(array('type' => 'group', 'principal' => 'dba', 'expires_at' => $date . 'T23:59:59Z'), json_decode($audit[1]['detail'], true));
	assert_same('s1', $audit[0]['server_id']);

	$f['creds']->unshare($f['boss'], $id, 'group', 'dba');
	assert_same(1, count($f['creds']->shares($id)));
	assert_same(null, $f['creds']->canUse($f['alice'], $id, CRD_NOW), 'unshared: alice lost it');
	$audit = $f['audit']->forCredential($id, 1);
	assert_same(VaultAudit::SHARE_REMOVED, $audit[0]['action']);
	assert_same(array('type' => 'group', 'principal' => 'dba'), json_decode($audit[0]['detail'], true));
	// Removing a share that isn't there changes nothing and writes no row.
	$f['creds']->unshare($f['boss'], $id, 'group', 'dba');
	assert_same(VaultAudit::SHARE_REMOVED, $f['audit']->forCredential($id, 1)[0]['action']);
	assert_same(4, count($f['audit']->forCredential($id, 10)));
}

function test_share_expiry_validation() {
	$f = creds_fixture();
	$id = make_shared($f['db'], $f['crypto'], 'Reporting');
	$c = $f['creds'];
	$boss = $f['boss'];
	assert_throws('VaultError', function () use ($c, $boss, $id) { $c->share($boss, $id, 'user', 'bob', share_today_offset(-1)); }, 'strvaultexpirypast');
	foreach (array('2026-13-01', '2026-02-30', '31/12/2099', '2099-12-31T00:00:00Z', ' 2099-12-31', '2099-12-31' . "\n") as $bad) {
		assert_throws('VaultError', function () use ($c, $boss, $id, $bad) { $c->share($boss, $id, 'user', 'bob', $bad); }, 'strvaultbadexpiry');
	}
	assert_same(array(), $c->shares($id), 'nothing was shared');
	$today = gmdate('Y-m-d');
	$c->share($boss, $id, 'user', 'bob', $today);
	assert_same($today . 'T23:59:59Z', $c->shares($id)[0]['expires_at']);
}

function test_share_principal_validation() {
	$f = creds_fixture();
	$id = make_shared($f['db'], $f['crypto'], 'Reporting');
	$c = $f['creds'];
	$boss = $f['boss'];
	foreach (array('', '   ', str_repeat('g', 129), "a\tb", "a\x7fb", "bad\xff") as $bad) {
		assert_throws('VaultError', function () use ($c, $boss, $id, $bad) { $c->share($boss, $id, 'group', $bad, null); }, 'strvaultbadprincipal');
	}
	assert_throws('VaultError', function () use ($c, $boss, $id) { $c->share($boss, $id, 'role', 'dba', null); }, 'strvaultbadsharetype');
	assert_throws('VaultError', function () use ($c, $boss, $id) { $c->unshare($boss, $id, 'role', 'dba'); }, 'strvaultbadsharetype');
	$long = str_repeat('é', 128);
	$c->share($boss, $id, 'group', $long, null);
	assert_same($long, $c->shares($id)[0]['principal']);
}

function test_share_admin_and_shared_only() {
	$f = creds_fixture();
	$shared = make_shared($f['db'], $f['crypto'], 'Reporting');
	$personal = $f['creds']->savePersonal($f['alice'], 's1', 'db1', 'u', 'pw', 'Mine');
	$c = $f['creds'];
	foreach (array(
		array($f['alice'], $shared),          // not an admin
		array($f['boss'], $personal),         // someone's personal login
		array($f['alice'], $personal),        // even its owner can't share it
		array($f['boss'], VaultStore::uuid()), // unknown
	) as $case) {
		list($who, $id) = $case;
		assert_throws('VaultError', function () use ($c, $who, $id) { $c->share($who, $id, 'user', 'bob', null); }, 'strvaultnotfound');
		assert_throws('VaultError', function () use ($c, $who, $id) { $c->unshare($who, $id, 'user', 'bob'); }, 'strvaultnotfound');
	}
	assert_same(0, (int)$f['db']->query('SELECT COUNT(*) FROM credential_shares')->fetchColumn());
}

function test_shared_all_summary() {
	$f = creds_fixture();
	$f['db']->exec("UPDATE servers SET name = 'Second', status = 'disabled' WHERE \"key\" = 's2'");
	$none = make_shared($f['db'], $f['crypto'], 'Lonely');
	$many = make_shared($f['db'], $f['crypto'], 'Busy');
	$exp = make_shared($f['db'], $f['crypto'], 'Temp', 's2');
	$gone = make_shared($f['db'], $f['crypto'], 'Gone');
	$f['creds']->savePersonal($f['alice'], 's1', 'db1', 'u', 'pw', 'Personal one');
	$f['creds']->share($f['boss'], $many, 'group', 'dba', null);
	$f['creds']->share($f['boss'], $many, 'group', 'finance', null);
	$f['creds']->share($f['boss'], $many, 'user', 'carol', null);
	$f['creds']->share($f['boss'], $exp, 'user', 'carol', '2099-11-30');
	$f['creds']->share($f['boss'], $exp, 'user', 'dave', '2099-12-15');
	$f['creds']->share($f['boss'], $exp, 'group', 'ops', null);
	make_share($f['db'], $gone, 'user', 'carol', '2020-01-01T23:59:59Z');

	$rows = $f['creds']->sharedAll();
	$by = array();
	foreach ($rows as $r) {
		$by[$r['label']] = $r;
		assert_true(!isset($r['password_enc']) && !isset($r['nonce']), 'no password fields');
	}
	assert_same(array('Busy', 'Gone', 'Lonely', 'Temp'), array_column($rows, 'label'), 'by server, then label; shared only');
	assert_same('not shared yet', $by['Lonely']['summary']);
	assert_same('2 groups, 1 user', $by['Busy']['summary']);
	assert_same('1 group, 2 users, expires 30 Nov 2099', $by['Temp']['summary']);
	assert_same('not shared yet', $by['Gone']['summary'], 'an expired share gives no access');
	assert_same('s1', $by['Busy']['server_name']);
	assert_same('ui', $by['Busy']['server_source']);
	assert_same('active', $by['Busy']['server_status']);
	assert_same('Second', $by['Temp']['server_name']);
	assert_same('disabled', $by['Temp']['server_status']);
	assert_same('db1', $by['Busy']['database']);
	assert_same('app', $by['Busy']['pg_username']);
	assert_same(array('dba', 'finance', 'ops'), $f['creds']->groupPrincipals());
}

function test_audit_page_hides_personal_labels() {
	$f = creds_fixture();
	$personal = $f['creds']->savePersonal($f['alice'], 's1', 'db1', 'u', 'pw', 'SecretPersonalLabel');
	$f['audit']->log('alice', VaultAudit::LOGIN_USED, array('credential_id' => $personal, 'server_id' => 's1', 'database' => 'db1'));
	$shared = make_shared($f['db'], $f['crypto'], 'Team login');
	$f['creds']->share($f['boss'], $shared, 'group', 'dba', null);
	$gone = make_shared($f['db'], $f['crypto'], 'Deleted login label');
	$f['creds']->share($f['boss'], $gone, 'group', 'dba', null);
	$f['creds']->delete($f['boss'], $gone);
	$f['audit']->log('boss', VaultAudit::USER_ADDED, array('detail' => array('user' => 'x')));

	$rows = $f['audit']->page(array(), null, 100);
	assert_same(6, count($rows));
	assert_true($rows[0]['id'] > $rows[1]['id'], 'newest first');
	assert_true(strpos(json_encode($rows), 'SecretPersonalLabel') === false, 'a personal label is in the audit page');
	assert_true(strpos(json_encode($rows), 'Deleted login label') === false, 'a deleted label is in the audit page');
	$state = array();
	foreach ($rows as $r) {
		$state[$r['action'] . ':' . (string)$r['credential_id']] = array($r['login'], $r['label']);
	}
	assert_same(array('none', null), $state[VaultAudit::USER_ADDED . ':']);
	assert_same(array('personal', null), $state[VaultAudit::LOGIN_USED . ':' . $personal]);
	assert_same(array('personal', null), $state[VaultAudit::LOGIN_SAVED . ':' . $personal]);
	assert_same(array('shared', 'Team login'), $state[VaultAudit::SHARE_ADDED . ':' . $shared]);
	assert_same(array('deleted', null), $state[VaultAudit::CREDENTIAL_DELETED . ':' . $gone]);

	// Filters and paging
	assert_same(2, count($f['audit']->page(array('actor' => 'alice'), null, 100)));
	assert_same(1, count($f['audit']->page(array('action' => VaultAudit::LOGIN_USED), null, 100)));
	assert_same(2, count($f['audit']->page(array('credential_id' => $gone), null, 100)));
	assert_same(1, count($f['audit']->page(array('actor' => 'alice', 'action' => VaultAudit::LOGIN_SAVED), null, 100)));
	assert_same(6, count($f['audit']->page(array('actor' => '', 'action' => '', 'credential_id' => ''), null, 100)), 'empty filters are ignored');
	$first = $f['audit']->page(array(), null, 3);
	assert_same(3, count($first));
	$next = $f['audit']->page(array(), (int)$first[2]['id'], 3);
	assert_same(3, count($next));
	assert_true($next[0]['id'] < $first[2]['id'], 'before is exclusive');
	assert_same(0, count($f['audit']->page(array(), (int)$next[2]['id'], 3)));
	assert_same(2, count($f['audit']->page(array(), (int)$first[0]['id'], 2)), 'limit');
}

function shared_form(array $over = array()): array {
	return $over + array('server_id' => 's1', 'database' => 'db1', 'pg_username' => 'app', 'password' => 'pw-1',
		'label' => 'Reports', 'access_label' => 'read-only');
}

function test_save_shared_stores_encrypted_and_audits() {
	$f = creds_fixture();
	$id = $f['creds']->saveShared($f['boss'], shared_form());
	$row = $f['db']->query("SELECT * FROM credentials WHERE id = '$id'")->fetch(PDO::FETCH_ASSOC);
	assert_same('shared', $row['kind']);
	assert_same('boss', $row['owner']);
	assert_same('Reports', $row['label']);
	assert_same('pw-1', $f['creds']->password($row));
	assert_true(strpos($row['password_enc'], 'pw-1') === false);
	$audit = $f['db']->query("SELECT action, detail FROM audit_log WHERE credential_id = '$id'")->fetchAll(PDO::FETCH_ASSOC);
	assert_same(1, count($audit));
	assert_same('login_saved', $audit[0]['action']);
	assert_same('{"kind":"shared"}', $audit[0]['detail']);
}

function test_save_shared_validates() {
	$f = creds_fixture();
	assert_throws('VaultError', function () use ($f) { $f['creds']->saveShared($f['boss'], shared_form(array('password' => ''))); }, 'strvaultbadpassword');
	assert_throws('VaultError', function () use ($f) { $f['creds']->saveShared($f['boss'], shared_form(array('server_id' => 'nope'))); }, 'strvaultservernotfound');
	assert_throws('VaultError', function () use ($f) { $f['creds']->saveShared($f['boss'], shared_form(array('label' => ''))); }, 'strvaultbadlabel');
	assert_throws('VaultError', function () use ($f) { $f['creds']->saveShared($f['alice'], shared_form()); }, 'strvaultnotfound');
	assert_same(0, (int) $f['db']->query('SELECT COUNT(*) FROM credentials')->fetchColumn());
}

function test_update_shared_blank_password_keeps_it() {
	$f = creds_fixture();
	$id = $f['creds']->saveShared($f['boss'], shared_form());
	$f['creds']->updateShared($f['boss'], $id, shared_form(array('password' => '', 'label' => 'Renamed', 'access_label' => 'read-write')));
	$row = $f['db']->query("SELECT * FROM credentials WHERE id = '$id'")->fetch(PDO::FETCH_ASSOC);
	assert_same('Renamed', $row['label']);
	assert_same('read-write', $row['access_label']);
	assert_same('pw-1', $f['creds']->password($row));
	$actions = $f['db']->query("SELECT action FROM audit_log WHERE credential_id = '$id' ORDER BY id")->fetchAll(PDO::FETCH_COLUMN);
	assert_same(array('login_saved', 'credential_changed'), $actions);
}

function test_update_shared_needs_password_when_target_changes() {
	$f = creds_fixture();
	$id = $f['creds']->saveShared($f['boss'], shared_form());
	foreach (array(array('pg_username' => 'other'), array('database' => 'db2'), array('server_id' => 's2')) as $change) {
		assert_throws('VaultError', function () use ($f, $id, $change) {
			$f['creds']->updateShared($f['boss'], $id, shared_form($change + array('password' => '')));
		}, 'strvaultneedpassword');
	}
	$row = $f['db']->query("SELECT * FROM credentials WHERE id = '$id'")->fetch(PDO::FETCH_ASSOC);
	assert_same('app', $row['pg_username']);
	assert_same('s1', $row['server_id']);
	assert_same('pw-1', $f['creds']->password($row));
}

function test_update_shared_rebinds_aad_and_audits_password() {
	$f = creds_fixture();
	$id = $f['creds']->saveShared($f['boss'], shared_form());
	$f['creds']->updateShared($f['boss'], $id, shared_form(array('server_id' => 's2', 'pg_username' => 'other', 'password' => 'pw-2')));
	$row = $f['db']->query("SELECT * FROM credentials WHERE id = '$id'")->fetch(PDO::FETCH_ASSOC);
	assert_same('s2', $row['server_id']);
	assert_same('other', $row['pg_username']);
	assert_same('pw-2', $f['creds']->password($row));
	// Bound to the new server and username: the old binding no longer opens it.
	assert_throws('VaultError', function () use ($f, $row) {
		$f['crypto']->decrypt($row['password_enc'], $row['nonce'], (int) $row['key_version'], VaultCrypto::aad($row['id'], 's1', 'app'));
	});
	$actions = $f['db']->query("SELECT action FROM audit_log WHERE credential_id = '$id' ORDER BY id")->fetchAll(PDO::FETCH_COLUMN);
	assert_same(array('login_saved', 'credential_changed', 'password_updated'), $actions);
}

function test_update_shared_admin_only_and_shared_only() {
	$f = creds_fixture();
	$id = $f['creds']->saveShared($f['boss'], shared_form());
	assert_throws('VaultError', function () use ($f, $id) { $f['creds']->updateShared($f['alice'], $id, shared_form()); }, 'strvaultnotfound');
	$personal = $f['creds']->savePersonal($f['boss'], 's1', 'db1', 'app', 'pw', 'Mine');
	assert_throws('VaultError', function () use ($f, $personal) { $f['creds']->updateShared($f['boss'], $personal, shared_form()); }, 'strvaultnotfound');
}

function test_save_personal_skips_identical_duplicate() {
	// Two first connects of the same login (two tabs) save it once.
	$f = creds_fixture();
	$c = $f['creds'];
	$id = $c->savePersonal($f['alice'], 's1', 'db1', 'alice_pg', 'pw1', ' My login ');
	assert_same($id, $c->savePersonal($f['alice'], 's1', 'db1', 'alice_pg', 'pw1', 'My login'));
	assert_same(1, (int)$f['db']->query("SELECT COUNT(*) FROM credentials")->fetchColumn());
	assert_same(1, (int)$f['db']->query("SELECT COUNT(*) FROM audit_log WHERE action = 'login_saved'")->fetchColumn());
	// Any difference is a new login: label, user, database, server, owner.
	$others = array(
		$c->savePersonal($f['alice'], 's1', 'db1', 'alice_pg', 'pw1', 'Other label'),
		$c->savePersonal($f['alice'], 's1', 'db1', 'other_pg', 'pw1', 'My login'),
		$c->savePersonal($f['alice'], 's1', 'db2', 'alice_pg', 'pw1', 'My login'),
		$c->savePersonal($f['alice'], 's2', 'db1', 'alice_pg', 'pw1', 'My login'),
		$c->savePersonal($f['bob'], 's1', 'db1', 'alice_pg', 'pw1', 'My login'),
	);
	assert_same(6, count(array_unique(array_merge($others, array($id)))));
	assert_same(6, (int)$f['db']->query("SELECT COUNT(*) FROM credentials")->fetchColumn());
}

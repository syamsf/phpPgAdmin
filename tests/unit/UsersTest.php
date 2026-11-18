<?php

require_once('./classes/vault/VaultStore.php');
require_once('./classes/vault/VaultAudit.php');
require_once('./classes/vault/VaultUsers.php');

/** A VaultUsers on a fresh vault file. */
function users_store() {
	$db = VaultStore::open(unit_tmp() . '/v.sqlite');
	return new VaultUsers($db, new VaultAudit($db));
}

/** $now plus $seconds, in VaultStore::now() format. */
function users_at(string $now, int $seconds) {
	return gmdate('Y-m-d\TH:i:s\Z', strtotime($now) + $seconds);
}

function test_add_hashes_argon2id() {
	$users = users_store();
	$users->add('alice', 'Alice', 'Alice-pass-123456', array('dba'), 'cli');
	$row = $users->get('alice');
	assert_true(strpos($row['password_hash'], '$argon2id$') === 0, 'hash is ' . $row['password_hash']);
	assert_same('Alice', $row['display_name']);
}

function test_add_audits_user_added() {
	$db = VaultStore::open(unit_tmp() . '/v.sqlite');
	$users = new VaultUsers($db, new VaultAudit($db));
	$users->add('alice', '', 'Alice-pass-123456', array('dba', 'role-admin'), 'cli');
	$row = $db->query("SELECT actor, action, detail FROM audit_log")->fetch();
	assert_same('cli', $row['actor']);
	assert_same(VaultAudit::USER_ADDED, $row['action']);
	assert_same(array('user' => 'alice', 'groups' => array('dba', 'role-admin')), json_decode($row['detail'], true));
	assert_true(strpos($row['detail'], 'Alice-pass') === false, 'the password is in the audit detail');
}

function test_add_rejects_short_password() {
	$users = users_store();
	assert_throws('VaultError', function () use ($users) {
		$users->add('alice', '', 'short-pass1', array(), 'cli');
	}, 'strvaultshortpassword');
	assert_same(null, $users->get('alice'));
}

function test_add_rejects_bad_username() {
	$users = users_store();
	foreach (array('', 'has space', 'semi;colon', str_repeat('a', 65), "new\nline") as $name) {
		assert_throws('VaultError', function () use ($users, $name) {
			$users->add($name, '', 'Alice-pass-123456', array(), 'cli');
		}, 'strvaultbadusername');
	}
	$users->add('a.b_c-d@example', '', 'Alice-pass-123456', array(), 'cli');
}

function test_add_rejects_duplicate() {
	$users = users_store();
	$users->add('alice', '', 'Alice-pass-123456', array(), 'cli');
	assert_throws('VaultError', function () use ($users) {
		$users->add('alice', '', 'Other-pass-123456', array(), 'cli');
	}, 'strvaultuserexists');
}

function test_verify_ok_and_bad() {
	$users = users_store();
	$users->add('alice', '', 'Alice-pass-123456', array(), 'cli');
	$now = VaultStore::now();
	assert_same('bad', $users->verify('alice', 'wrong-password-1', $now));
	assert_same(1, (int)$users->get('alice')['failed_attempts']);
	assert_same('ok', $users->verify('alice', 'Alice-pass-123456', $now));
	assert_same(0, (int)$users->get('alice')['failed_attempts'], 'ok resets the counter');
}

function test_lockout_after_five() {
	$users = users_store();
	$users->add('alice', '', 'Alice-pass-123456', array(), 'cli');
	$now = VaultStore::now();
	for ($i = 1; $i <= 5; $i++) {
		assert_same('bad', $users->verify('alice', 'wrong-password-' . $i, $now), "attempt $i");
	}
	$row = $users->get('alice');
	assert_same(0, (int)$row['failed_attempts'], 'the counter starts again');
	assert_same(users_at($now, 300), $row['locked_until']);
	assert_same('locked', $users->verify('alice', 'Alice-pass-123456', $now));
	assert_same('locked', $users->verify('alice', 'Alice-pass-123456', users_at($now, 299)));
	assert_same('ok', $users->verify('alice', 'Alice-pass-123456', users_at($now, 301)));
}

function test_unknown_user_is_bad() {
	$users = users_store();
	assert_same('bad', $users->verify('nobody', 'Whatever-pass-1', VaultStore::now()));
	assert_same(null, $users->get('nobody'), 'no row is made for an unknown name');
}

function test_disabled_is_disabled() {
	$db = VaultStore::open(unit_tmp() . '/v.sqlite');
	$users = new VaultUsers($db, new VaultAudit($db));
	$users->add('alice', '', 'Alice-pass-123456', array(), 'cli');
	$db->exec("UPDATE users SET disabled = 1 WHERE username = 'alice'");
	assert_same('disabled', $users->verify('alice', 'Alice-pass-123456', VaultStore::now()));
}

function test_groups_of_sorted() {
	$users = users_store();
	$users->add('alice', '', 'Alice-pass-123456', array('zeta', ' dba ', 'alpha', 'dba', ''), 'cli');
	assert_same(array('alpha', 'dba', 'zeta'), $users->groupsOf('alice'));
	assert_same(array(), $users->groupsOf('nobody'));
}

function test_all_lists_users_with_groups() {
	$users = users_store();
	$users->add('bob', 'Bob', 'Bob-pass-1234567', array('dba'), 'cli');
	$users->add('alice', '', 'Alice-pass-123456', array(), 'cli');
	$all = $users->all();
	assert_same(array('alice', 'bob'), array($all[0]['username'], $all[1]['username']));
	assert_same(array('dba'), $all[1]['groups']);
	assert_same(false, $all[0]['disabled']);
	assert_same('Bob', $all[1]['display_name']);
	assert_same(1, preg_match('/^\d{4}-\d\d-\d\dT/', (string) $all[0]['created_at']));
}

function test_set_disabled_deletes_direct_shares() {
	$db = VaultStore::open(unit_tmp() . '/v.sqlite');
	$users = new VaultUsers($db, new VaultAudit($db));
	$users->add('alice', '', 'Alice-pass-123456', array(), 'cli');
	$db->exec("PRAGMA foreign_keys=OFF");
	$cols = array_column($db->query('PRAGMA table_info(credential_shares)')->fetchAll(), 'name');
	$ins = function ($type, $principal) use ($db, $cols) {
		$vals = array();
		foreach ($cols as $c) {
			$vals[$c] = $c === 'principal_type' ? $type : ($c === 'principal' ? $principal : 'x-' . $type . $principal . $c);
		}
		$db->prepare('INSERT INTO credential_shares (' . implode(',', array_map(function ($c) { return '"' . $c . '"'; }, $cols))
			. ') VALUES (' . implode(',', array_fill(0, count($cols), '?')) . ')')->execute(array_values($vals));
	};
	$ins('user', 'alice');
	$ins('group', 'alice');
	$users->setDisabled('alice', true, 'admin');
	assert_same(true, $users->isDisabled('alice'));
	$left = $db->query('SELECT principal_type FROM credential_shares')->fetchAll(PDO::FETCH_COLUMN);
	assert_same(array('group'), $left, 'only the group share is left');
	assert_same(1, (int)$db->query("SELECT COUNT(*) FROM audit_log WHERE action = 'user_disabled'")->fetchColumn());
	$users->setDisabled('alice', false, 'admin');
	assert_same(false, $users->isDisabled('alice'));
	assert_same(1, (int)$db->query("SELECT COUNT(*) FROM audit_log WHERE action = 'user_enabled'")->fetchColumn());
	assert_throws('VaultError', function () use ($users) {
		$users->setDisabled('nobody', true, 'admin');
	}, 'strvaultusernotfound');
}

function test_reset_password_clears_lockout() {
	$db = VaultStore::open(unit_tmp() . '/v.sqlite');
	$users = new VaultUsers($db, new VaultAudit($db));
	$users->add('alice', '', 'Alice-pass-123456', array(), 'cli');
	$now = VaultStore::now();
	for ($i = 0; $i < 5; $i++) {
		$users->verify('alice', 'wrong-pass-123456', $now);
	}
	assert_same('locked', $users->verify('alice', 'Alice-pass-123456', $now));
	assert_throws('VaultError', function () use ($users) {
		$users->resetPassword('alice', 'short', 'admin');
	}, 'strvaultshortpassword');
	$users->resetPassword('alice', 'New-pass-1234567', 'admin');
	assert_same('bad', $users->verify('alice', 'Alice-pass-123456', $now));
	assert_same('ok', $users->verify('alice', 'New-pass-1234567', $now));
	$detail = $db->query("SELECT detail FROM audit_log WHERE action = 'password_reset'")->fetchColumn();
	assert_true(strpos($detail, 'pass') === false, 'a password is in the audit detail');
}

function test_set_groups_audits_before_and_after() {
	$db = VaultStore::open(unit_tmp() . '/v.sqlite');
	$users = new VaultUsers($db, new VaultAudit($db));
	$users->add('alice', '', 'Alice-pass-123456', array('dba'), 'cli');
	$users->setGroups('alice', array(' ops ', 'dev', 'ops', ''), 'admin');
	assert_same(array('dev', 'ops'), $users->groupsOf('alice'));
	$detail = json_decode($db->query("SELECT detail FROM audit_log WHERE action = 'groups_changed'")->fetchColumn(), true);
	assert_same(array('user' => 'alice', 'before' => array('dba'), 'after' => array('dev', 'ops')), $detail);
	assert_throws('VaultError', function () use ($users) {
		$users->setGroups('alice', array(str_repeat('g', 65)), 'admin');
	}, 'strvaultbadgroup');
	assert_same(array('dev', 'ops'), $users->groupsOf('alice'));
}

function test_failed_write_rolls_back_for_the_next_one() {
	// PHP < 8.4 doesn't see a BEGIN sent with exec(): a guard on
	// inTransaction() left the transaction open, and the next write on the
	// same connection failed with "cannot start a transaction within a transaction".
	$db = VaultStore::open(unit_tmp() . '/v.sqlite');
	$users = new VaultUsers($db, new VaultAudit($db));
	$users->add('alice', '', 'Alice-pass-123456', array('dba'), 'cli');
	assert_throws('VaultError', function () use ($users) {
		$users->add('alice', '', 'Alice-pass-123456', array(), 'cli');
	}, 'strvaultuserexists');
	$users->setGroups('alice', array('ops'), 'admin');
	assert_throws('VaultError', function () use ($users) {
		$users->setDisabled('nobody', true, 'admin');
	}, 'strvaultusernotfound');
	assert_throws('VaultError', function () use ($users) {
		$users->resetPassword('nobody', 'New-pass-1234567', 'admin');
	}, 'strvaultusernotfound');
	$users->setDisabled('alice', true, 'admin');
	assert_same(array('ops'), $users->groupsOf('alice'));
	assert_same(true, $users->isDisabled('alice'));
	assert_same(1, (int)$db->query("SELECT COUNT(*) FROM users")->fetchColumn());
}

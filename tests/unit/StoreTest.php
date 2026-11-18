<?php

require_once('./classes/vault/VaultStore.php');

function test_open_creates_private_file() {
	$path = unit_tmp() . '/sub/v.sqlite';
	VaultStore::open($path);
	assert_same(0600, fileperms($path) & 0777, 'file mode');
	assert_same(0700, fileperms(dirname($path)) & 0777, 'dir mode');
}

function test_pragmas_set() {
	$pdo = VaultStore::open(unit_tmp() . '/v.sqlite');
	assert_same('wal', $pdo->query('PRAGMA journal_mode')->fetchColumn());
	assert_same(1, (int)$pdo->query('PRAGMA foreign_keys')->fetchColumn());
	assert_same(5000, (int)$pdo->query('PRAGMA busy_timeout')->fetchColumn());
}

function test_schema_applied_once() {
	$path = unit_tmp() . '/v.sqlite';
	VaultStore::open($path);
	$pdo = VaultStore::open($path);
	assert_same(1, (int)$pdo->query('PRAGMA user_version')->fetchColumn());
	$tables = $pdo->query("SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%' ORDER BY name")
		->fetchAll(PDO::FETCH_COLUMN);
	assert_same(['audit_log', 'credential_shares', 'credentials', 'servers', 'user_groups', 'users'], $tables);
}

function test_delete_server_cascades() {
	$pdo = VaultStore::open(unit_tmp() . '/v.sqlite');
	$now = VaultStore::now();
	$pdo->prepare('INSERT INTO servers ("key", name, source, host, default_db, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)')
		->execute(['reporting-replica', 'Reporting', 'ui', 'db.example.internal', 'postgres', $now, $now]);
	$pdo->prepare('INSERT INTO credentials (id, kind, owner, label, server_id, "database", pg_username, password_enc, nonce, key_version, access_label, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)')
		->execute([VaultStore::uuid(), 'shared', 'admin', 'Reports', 'reporting-replica', 'postgres', 'report', 'x', 'y', 1, 'read-only', $now, $now]);
	assert_same(1, (int)$pdo->query('SELECT COUNT(*) FROM credentials')->fetchColumn());
	$pdo->exec('DELETE FROM servers');
	assert_same(0, (int)$pdo->query('SELECT COUNT(*) FROM credentials')->fetchColumn());
}

function test_now_format() {
	assert_same(1, preg_match('/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$/', VaultStore::now()));
}

function test_uuid_v4() {
	$a = VaultStore::uuid();
	assert_same(1, preg_match('/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/', $a));
	assert_true($a !== VaultStore::uuid(), 'two uuids differ');
}

function test_transaction_rolls_back_and_frees_the_connection() {
	$pdo = VaultStore::open(unit_tmp() . '/v.sqlite');
	$insert = function (string $name) use ($pdo) {
		$pdo->prepare('INSERT INTO users (username, created_at) VALUES (?, ?)')->execute(array($name, VaultStore::now()));
	};
	assert_throws('VaultError', function () use ($pdo, $insert) {
		VaultStore::transaction($pdo, function () use ($insert) {
			$insert('alice');
			throw new VaultError('strvaultuserexists');
		});
	}, 'strvaultuserexists');
	assert_same(0, (int)$pdo->query('SELECT COUNT(*) FROM users')->fetchColumn(), 'rolled back');
	// The next write on the same connection works and commits.
	assert_same('done', VaultStore::transaction($pdo, function () use ($insert) {
		$insert('bob');
		return 'done';
	}));
	assert_same(array('bob'), $pdo->query('SELECT username FROM users')->fetchAll(PDO::FETCH_COLUMN));
	// A plain write after it is outside any transaction (autocommit).
	$insert('carol');
	$other = new PDO('sqlite:' . $pdo->query('PRAGMA database_list')->fetch(PDO::FETCH_ASSOC)['file']);
	assert_same(2, (int)$other->query('SELECT COUNT(*) FROM users')->fetchColumn(), 'committed for other connections');
}

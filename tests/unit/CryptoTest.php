<?php

require_once('./classes/vault/VaultCrypto.php');

function crypto_key($fill = 'k') {
	return str_repeat($fill, 32);
}

function test_roundtrip() {
	$c = new VaultCrypto([1 => crypto_key()], 1);
	list($cipher, $nonce, $ver) = $c->encrypt('s3cret pass', 'aad');
	assert_same(1, $ver);
	assert_true($cipher !== 's3cret pass', 'ciphertext differs');
	assert_same('s3cret pass', $c->decrypt($cipher, $nonce, $ver, 'aad'));
}

function test_nonce_is_fresh() {
	$c = new VaultCrypto([1 => crypto_key()], 1);
	$a = $c->encrypt('same', 'aad');
	$b = $c->encrypt('same', 'aad');
	assert_same(24, strlen($a[1]));
	assert_same(24, strlen($b[1]));
	assert_true($a[1] !== $b[1], 'nonces differ');
}

function test_decrypt_fails_on_wrong_aad() {
	$c = new VaultCrypto([1 => crypto_key()], 1);
	list($cipher, $nonce, $ver) = $c->encrypt('pw', VaultCrypto::aad('id1', 'srv', 'bob'));
	assert_throws('VaultError', function () use ($c, $cipher, $nonce, $ver) {
		$c->decrypt($cipher, $nonce, $ver, VaultCrypto::aad('id2', 'srv', 'bob'));
	});
}

function test_decrypt_fails_with_other_key() {
	$c = new VaultCrypto([1 => crypto_key('a')], 1);
	$d = new VaultCrypto([1 => crypto_key('b')], 1);
	list($cipher, $nonce, $ver) = $c->encrypt('pw', 'aad');
	assert_throws('VaultError', function () use ($d, $cipher, $nonce, $ver) {
		$d->decrypt($cipher, $nonce, $ver, 'aad');
	});
}

function test_unknown_version_throws() {
	$c = new VaultCrypto([1 => crypto_key()], 1);
	list($cipher, $nonce) = $c->encrypt('pw', 'aad');
	assert_throws('VaultError', function () use ($c, $cipher, $nonce) {
		$c->decrypt($cipher, $nonce, 9, 'aad');
	});
}

function test_aad_format() {
	assert_same("id\0srv\0bob", VaultCrypto::aad('id', 'srv', 'bob'));
}

function test_key_file_wins_over_env() {
	$file = unit_tmp() . '/vault.key';
	file_put_contents($file, base64_encode(crypto_key('f')) . "\n");
	$fromFile = VaultCrypto::fromConfig(['key_file' => $file, 'key' => base64_encode(crypto_key('e'))]);
	$ref = new VaultCrypto([1 => crypto_key('f')], 1);
	list($cipher, $nonce, $ver) = $ref->encrypt('pw', 'aad');
	assert_same('pw', $fromFile->decrypt($cipher, $nonce, $ver, 'aad'));
}

function test_key_from_env() {
	$c = VaultCrypto::fromConfig(['key_file' => '', 'key' => base64_encode(crypto_key('e'))]);
	$ref = new VaultCrypto([1 => crypto_key('e')], 1);
	list($cipher, $nonce, $ver) = $ref->encrypt('pw', 'aad');
	assert_same('pw', $c->decrypt($cipher, $nonce, $ver, 'aad'));
}

function test_short_key_rejected() {
	assert_throws('VaultError', function () {
		VaultCrypto::fromConfig(['key' => base64_encode(str_repeat('x', 16))]);
	}, 'VAULT_KEY');
}

function test_bad_base64_rejected() {
	assert_throws('VaultError', function () {
		VaultCrypto::fromConfig(['key' => '!!not base64!!']);
	}, 'VAULT_KEY');
}

function test_short_key_file_names_file() {
	$file = unit_tmp() . '/short.key';
	file_put_contents($file, base64_encode(str_repeat('x', 16)));
	assert_throws('VaultError', function () use ($file) {
		VaultCrypto::fromConfig(['key_file' => $file]);
	}, 'VAULT_KEY_FILE');
}

function test_unreadable_key_file_rejected() {
	assert_throws('VaultError', function () {
		VaultCrypto::fromConfig(['key_file' => unit_tmp() . '/nope.key']);
	}, 'VAULT_KEY_FILE');
}

function test_missing_key_rejected() {
	assert_throws('VaultError', function () {
		VaultCrypto::fromConfig([]);
	}, 'VAULT_KEY_FILE or VAULT_KEY must be set');
	assert_throws('VaultError', function () {
		VaultCrypto::fromConfig(['key_file' => '', 'key' => '']);
	}, 'VAULT_KEY_FILE or VAULT_KEY must be set');
}

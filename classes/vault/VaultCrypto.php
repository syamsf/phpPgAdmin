<?php

require_once('./classes/vault/VaultError.php');

/**
 * Encrypts saved login passwords with XChaCha20-Poly1305. The additional
 * data ties a ciphertext to its row, so copying it elsewhere fails to decrypt.
 */
class VaultCrypto {

	private $keys;
	private $current;

	/**
	 * @param array $keys version => 32-byte binary key
	 * @param int $current version used by encrypt()
	 */
	public function __construct(array $keys, $current) {
		if (!isset($keys[$current])) {
			throw new VaultError('Vault key version ' . (int)$current . ' is not available');
		}
		$this->keys = $keys;
		$this->current = (int)$current;
	}

	/**
	 * @param array $cfg with optional 'key_file' and 'key' (base64 of 32 bytes); the file wins
	 */
	public static function fromConfig(array $cfg) {
		$file = isset($cfg['key_file']) ? (string)$cfg['key_file'] : '';
		$inline = isset($cfg['key']) ? (string)$cfg['key'] : '';

		if ($file !== '') {
			$name = 'VAULT_KEY_FILE';
			$raw = is_file($file) && is_readable($file) ? @file_get_contents($file) : false;
			if ($raw === false) {
				throw new VaultError('VAULT_KEY_FILE can\'t be read');
			}
		} elseif ($inline !== '') {
			$name = 'VAULT_KEY';
			$raw = $inline;
		} else {
			throw new VaultError('VAULT_KEY_FILE or VAULT_KEY must be set');
		}

		$key = base64_decode(trim($raw), true);
		if ($key === false || strlen($key) !== SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_KEYBYTES) {
			throw new VaultError($name . ' must be the base64 of exactly 32 bytes');
		}
		return new VaultCrypto([1 => $key], 1);
	}

	public static function aad($credId, $serverKey, $pgUser) {
		return $credId . "\0" . $serverKey . "\0" . $pgUser;
	}

	/**
	 * @return array [ciphertext, nonce, key version]
	 */
	public function encrypt($plain, $aad) {
		$nonce = random_bytes(SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES);
		$cipher = sodium_crypto_aead_xchacha20poly1305_ietf_encrypt($plain, $aad, $nonce, $this->keys[$this->current]);
		return [$cipher, $nonce, $this->current];
	}

	public function decrypt($cipher, $nonce, $version, $aad) {
		if (!isset($this->keys[$version])) {
			throw new VaultError('Unknown vault key version ' . (int)$version);
		}
		if (strlen($nonce) !== SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES) {
			throw new VaultError('This saved login can\'t be decrypted. Update its password.');
		}
		$plain = sodium_crypto_aead_xchacha20poly1305_ietf_decrypt($cipher, $aad, $nonce, $this->keys[$version]);
		if ($plain === false) {
			throw new VaultError('This saved login can\'t be decrypted. Update its password.');
		}
		return $plain;
	}
}

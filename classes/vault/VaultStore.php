<?php

require_once(__DIR__ . '/VaultError.php');

/**
 * Opens the login vault's SQLite file and applies the schema on first use.
 */
class VaultStore {

	const SCHEMA_VERSION = 1;

	/**
	 * Open (and create, if needed) the vault database at $path.
	 * The directory is 0700 and the file 0600.
	 * @throws VaultError
	 */
	public static function open(string $path): PDO {
		$old = umask(0077);
		try {
			$dir = dirname($path);
			if (!is_dir($dir) && !@mkdir($dir, 0700, true) && !is_dir($dir)) {
				throw new VaultError("Can't create the vault directory for {$path}.");
			}
			if (!file_exists($path) && @file_put_contents($path, '') === false) {
				throw new VaultError("Can't create the vault file {$path}.");
			}
			@chmod($path, 0600);

			$pdo = new PDO('sqlite:' . $path);
			$pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
			$pdo->setAttribute(PDO::ATTR_DEFAULT_FETCH_MODE, PDO::FETCH_ASSOC);
			$pdo->exec('PRAGMA busy_timeout=5000');
			$pdo->exec('PRAGMA journal_mode=WAL');
			$pdo->exec('PRAGMA foreign_keys=ON');

			$version = (int)$pdo->query('PRAGMA user_version')->fetchColumn();
			if ($version === 0) {
				$sql = file_get_contents(__DIR__ . '/schema.sqlite.sql');
				if ($sql === false) {
					throw new VaultError("Can't read the vault schema file.");
				}
				self::transaction($pdo, function () use ($pdo, $sql) {
					// Another process may have applied it while we waited for the lock.
					if ((int)$pdo->query('PRAGMA user_version')->fetchColumn() === 0) {
						$pdo->exec($sql);
						$pdo->exec('PRAGMA user_version = ' . self::SCHEMA_VERSION);
					}
				});
			}
			return $pdo;
		} catch (VaultError $e) {
			throw $e;
		} catch (Exception $e) {
			throw new VaultError("Can't open the vault database {$path}: " . $e->getMessage(), 0, $e);
		} finally {
			umask($old);
		}
	}

	/**
	 * Runs $fn in a write transaction (BEGIN IMMEDIATE) and commits; on any
	 * exception rolls back and rethrows. Returns what $fn returns.
	 *
	 * The ROLLBACK is unconditional: PHP < 8.4 doesn't see a BEGIN sent
	 * through exec(), so inTransaction() is false there and a guard on it
	 * would leave the transaction open for the next write on this
	 * connection. A failed COMMIT may already have ended it, hence the catch.
	 */
	public static function transaction(PDO $db, callable $fn) {
		$db->exec('BEGIN IMMEDIATE');
		try {
			$result = $fn();
			$db->exec('COMMIT');
			return $result;
		} catch (Throwable $e) {
			try {
				$db->exec('ROLLBACK');
			} catch (PDOException $ignored) {
			}
			throw $e;
		}
	}

	/** Current UTC time as text, e.g. 2026-11-18T09:30:00Z. */
	public static function now(): string {
		return gmdate('Y-m-d\TH:i:s\Z');
	}

	/** A random UUID v4. */
	public static function uuid(): string {
		$b = random_bytes(16);
		$b[6] = chr((ord($b[6]) & 0x0f) | 0x40);
		$b[8] = chr((ord($b[8]) & 0x3f) | 0x80);
		$h = bin2hex($b);
		return substr($h, 0, 8) . '-' . substr($h, 8, 4) . '-' . substr($h, 12, 4)
			. '-' . substr($h, 16, 4) . '-' . substr($h, 20, 12);
	}
}

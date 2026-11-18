<?php

require_once(__DIR__ . '/VaultStore.php');

/**
 * The app's audit log: who did what with which saved login. The detail
 * never holds a password.
 */
class VaultAudit {

	const LOGIN_SAVED = 'login_saved';
	const LOGIN_USED = 'login_used';
	const LOGIN_FAILED = 'login_failed';
	const SHARE_ADDED = 'share_added';
	const SHARE_REMOVED = 'share_removed';
	const PASSWORD_UPDATED = 'password_updated';
	const CREDENTIAL_CHANGED = 'credential_changed';
	const CREDENTIAL_DELETED = 'credential_deleted';
	const USER_ADDED = 'user_added';
	const USER_DISABLED = 'user_disabled';
	const USER_ENABLED = 'user_enabled';
	const PASSWORD_RESET = 'password_reset';
	const GROUPS_CHANGED = 'groups_changed';
	const SIGNIN_FAILED = 'signin_failed';
	const SERVER_ADDED = 'server_added';
	const SERVER_CHANGED = 'server_changed';
	const SERVER_DELETED = 'server_deleted';

	private $db;

	public function __construct(PDO $db) {
		$this->db = $db;
	}

	/**
	 * @param array $ctx optional credential_id, server_id, database, detail (array)
	 */
	public function log(string $actor, string $action, array $ctx = array()): void {
		$detail = isset($ctx['detail']) && is_array($ctx['detail']) && $ctx['detail'] ? $ctx['detail'] : new stdClass();
		$stmt = $this->db->prepare('INSERT INTO audit_log (at, actor, action, credential_id, server_id, "database", client_ip, detail)
			VALUES (:at, :actor, :action, :credential_id, :server_id, :database, :client_ip, :detail)');
		$stmt->execute(array(
			':at' => VaultStore::now(),
			':actor' => $actor,
			':action' => $action,
			':credential_id' => isset($ctx['credential_id']) ? (string)$ctx['credential_id'] : null,
			':server_id' => isset($ctx['server_id']) ? (string)$ctx['server_id'] : null,
			':database' => isset($ctx['database']) ? (string)$ctx['database'] : null,
			':client_ip' => isset($_SERVER['REMOTE_ADDR']) ? (string)$_SERVER['REMOTE_ADDR'] : null,
			':detail' => json_encode($detail, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE),
		));
	}

	/**
	 * Seconds until this person may try this server again: 0 unless there
	 * are 5 or more login_failed rows for a wrong password in the last
	 * 300 s, then until the oldest of the newest five is 300 s old. Other
	 * failures (a missing database, an unreachable host) are audited too
	 * but aren't password guessing, so they don't count.
	 */
	public function loginLockSeconds(string $actor, string $serverKey, int $nowTs): int {
		$stmt = $this->db->prepare('SELECT at FROM audit_log
			WHERE actor = :actor AND action = :action AND server_id = :server AND at > :since
				AND json_extract(detail, \'$.reason\') = \'strloginbadpassword\'
			ORDER BY at DESC, id DESC LIMIT 5');
		$stmt->execute(array(
			':actor' => $actor,
			':action' => self::LOGIN_FAILED,
			':server' => $serverKey,
			':since' => gmdate('Y-m-d\TH:i:s\Z', $nowTs - 300),
		));
		$times = $stmt->fetchAll(PDO::FETCH_COLUMN);
		if (count($times) < 5) {
			return 0;
		}
		$oldest = strtotime($times[4]);
		return $oldest === false ? 0 : max(0, $oldest + 300 - $nowTs);
	}

	/**
	 * One page of the audit log for admins, newest first.
	 * @param array $filter optional credential_id, actor, action (exact
	 *   matches; empty values are ignored)
	 * @param int|null $beforeId only rows older than this id (the next page)
	 * @return array audit rows plus:
	 *   - login: 'shared' (a shared login that still exists), 'personal'
	 *     (someone's own login: never named here), 'deleted', or 'none'
	 *   - label: the shared login's label, else null
	 */
	public function page(array $filter, ?int $beforeId, int $limit): array {
		$where = array();
		$bind = array();
		foreach (array('credential_id' => 'a.credential_id', 'actor' => 'a.actor', 'action' => 'a.action') as $key => $col) {
			if (isset($filter[$key]) && is_string($filter[$key]) && $filter[$key] !== '') {
				$where[] = $col . ' = :' . $key;
				$bind[':' . $key] = $filter[$key];
			}
		}
		if ($beforeId !== null) {
			$where[] = 'a.id < :before';
			$bind[':before'] = $beforeId;
		}
		$stmt = $this->db->prepare('SELECT a.*, c.kind AS credential_kind,
				CASE WHEN c.kind = \'shared\' THEN c.label END AS label
			FROM audit_log a LEFT JOIN credentials c ON c.id = a.credential_id'
			. ($where ? ' WHERE ' . implode(' AND ', $where) : '')
			. ' ORDER BY a.id DESC LIMIT :limit');
		foreach ($bind as $k => $v) {
			$stmt->bindValue($k, $v, is_int($v) ? PDO::PARAM_INT : PDO::PARAM_STR);
		}
		$stmt->bindValue(':limit', max(1, $limit), PDO::PARAM_INT);
		$stmt->execute();
		$rows = array();
		foreach ($stmt->fetchAll(PDO::FETCH_ASSOC) as $row) {
			if ($row['credential_id'] === null || $row['credential_id'] === '') {
				$row['login'] = 'none';
			} elseif ($row['credential_kind'] === null) {
				$row['login'] = 'deleted';
			} else {
				$row['login'] = $row['credential_kind'] === 'shared' ? 'shared' : 'personal';
			}
			unset($row['credential_kind']);
			$rows[] = $row;
		}
		return $rows;
	}

	/** Audit rows for one credential, newest first. */
	public function forCredential(string $id, int $limit): array {
		$stmt = $this->db->prepare('SELECT * FROM audit_log WHERE credential_id = :id ORDER BY id DESC LIMIT :limit');
		$stmt->bindValue(':id', $id);
		$stmt->bindValue(':limit', max(1, $limit), PDO::PARAM_INT);
		$stmt->execute();
		return $stmt->fetchAll(PDO::FETCH_ASSOC);
	}
}

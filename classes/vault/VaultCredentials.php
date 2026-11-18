<?php

require_once(__DIR__ . '/VaultError.php');
require_once(__DIR__ . '/VaultStore.php');
require_once(__DIR__ . '/VaultCrypto.php');
require_once(__DIR__ . '/VaultIdentity.php');
require_once(__DIR__ . '/VaultAudit.php');

/**
 * Saved logins. Visibility is decided here and nowhere else:
 * - a personal login is visible only to its owner (admins included);
 * - a shared login is visible only through an unexpired share to the user
 *   or to one of their groups;
 * - a login on a server that isn't active is visible to nobody.
 * An id the caller may not touch is treated exactly like an unknown id.
 */
class VaultCredentials {

	private $db;
	private $crypto;
	private $audit;

	public function __construct(PDO $db, VaultCrypto $crypto, VaultAudit $audit) {
		$this->db = $db;
		$this->crypto = $crypto;
		$this->audit = $audit;
	}

	/**
	 * Saves a personal login. When the owner already has one with the same
	 * server, database, Postgres user and label (two tabs saving the same
	 * first login), nothing is added and that one's id is returned.
	 * @return string the credential's id
	 */
	public function savePersonal(VaultIdentity $who, string $serverKey, string $database, string $pgUser,
			string $password, string $label, string $access = 'read-write'): string {
		$label = trim($label);
		$this->validate($label, $pgUser, $database, $password, $access);
		// One write transaction: two parallel saves can't both miss the other.
		return VaultStore::transaction($this->db, function () use ($who, $serverKey, $database, $pgUser, $password, $label, $access) {
			$stmt = $this->db->prepare('SELECT 1 FROM servers WHERE "key" = :k AND status = \'active\'');
			$stmt->execute(array(':k' => $serverKey));
			if ($stmt->fetchColumn() === false) {
				throw new VaultError('strvaultservernotfound');
			}
			$stmt = $this->db->prepare('SELECT id FROM credentials WHERE kind = \'personal\' AND owner = :owner
				AND server_id = :server AND "database" = :database AND pg_username = :pg AND label = :label LIMIT 1');
			$stmt->execute(array(':owner' => $who->username, ':server' => $serverKey, ':database' => $database,
				':pg' => $pgUser, ':label' => $label));
			$existing = $stmt->fetchColumn();
			if ($existing !== false) {
				return (string)$existing;
			}

			$id = VaultStore::uuid();
			list($cipher, $nonce, $version) = $this->crypto->encrypt($password, VaultCrypto::aad($id, $serverKey, $pgUser));
			$now = VaultStore::now();
			$stmt = $this->db->prepare('INSERT INTO credentials
				(id, kind, owner, label, server_id, "database", pg_username, password_enc, nonce, key_version, access_label, created_at, updated_at)
				VALUES (:id, \'personal\', :owner, :label, :server, :database, :pg, :enc, :nonce, :ver, :access, :now, :now)');
			$stmt->bindValue(':id', $id);
			$stmt->bindValue(':owner', $who->username);
			$stmt->bindValue(':label', $label);
			$stmt->bindValue(':server', $serverKey);
			$stmt->bindValue(':database', $database);
			$stmt->bindValue(':pg', $pgUser);
			$stmt->bindValue(':enc', $cipher, PDO::PARAM_LOB);
			$stmt->bindValue(':nonce', $nonce, PDO::PARAM_LOB);
			$stmt->bindValue(':ver', $version, PDO::PARAM_INT);
			$stmt->bindValue(':access', $access);
			$stmt->bindValue(':now', $now);
			$stmt->execute();

			$this->audit->log($who->username, VaultAudit::LOGIN_SAVED, array(
				'credential_id' => $id, 'server_id' => $serverKey, 'database' => $database,
				'detail' => array('kind' => 'personal', 'pg_username' => $pgUser),
			));
			return $id;
		});
	}

	/**
	 * The logins this person can pick for one server and database: their own
	 * first, then the shared ones, each sorted by label.
	 */
	public function listFor(VaultIdentity $who, string $serverKey, string $database, string $now): array {
		$stmt = $this->db->prepare('SELECT c.id, c.kind, c.label, c.pg_username, c.access_label, c.last_used_at, c.last_status
			FROM credentials c JOIN servers sv ON sv."key" = c.server_id AND sv.status = \'active\'
			WHERE c.kind = \'personal\' AND c.owner = :owner AND c.server_id = :server AND c."database" = :database
			ORDER BY c.label, c.id');
		$stmt->execute(array(':owner' => $who->username, ':server' => $serverKey, ':database' => $database));
		$rows = array();
		foreach ($stmt->fetchAll(PDO::FETCH_ASSOC) as $row) {
			$row['via'] = null;
			$row['expires_at'] = null;
			$rows[] = $row;
		}
		foreach ($this->sharedRows($who, $now, 'c.server_id = :server AND c."database" = :database',
				array(':server' => $serverKey, ':database' => $database), false) as $row) {
			$rows[] = $row;
		}
		return $rows;
	}

	/**
	 * One login if this person may use it, with the encrypted password
	 * fields; null otherwise (unknown id, someone else's, no valid share,
	 * server not active).
	 */
	public function canUse(VaultIdentity $who, string $id, string $now): ?array {
		$stmt = $this->db->prepare('SELECT c.* FROM credentials c
			JOIN servers sv ON sv."key" = c.server_id AND sv.status = \'active\'
			WHERE c.id = :id AND c.kind = \'personal\' AND c.owner = :owner');
		$stmt->execute(array(':id' => $id, ':owner' => $who->username));
		$row = $stmt->fetch(PDO::FETCH_ASSOC);
		if ($row !== false) {
			$row['via'] = null;
			$row['expires_at'] = null;
			return $row;
		}
		$rows = $this->sharedRows($who, $now, 'c.id = :id', array(':id' => $id), true);
		return $rows ? $rows[0] : null;
	}

	/** The plain password. @throws VaultError when it can't be decrypted */
	public function password(array $row): string {
		return $this->crypto->decrypt($row['password_enc'], $row['nonce'], (int)$row['key_version'],
			VaultCrypto::aad($row['id'], $row['server_id'], $row['pg_username']));
	}

	/** For edit forms: no password fields. Owner of a personal row, admin for a shared one. */
	public function get(VaultIdentity $who, string $id): ?array {
		$row = $this->manageable($who, $id);
		if ($row === null) {
			return null;
		}
		unset($row['password_enc'], $row['nonce']);
		return $row;
	}

	public function markUsed(string $id, string $now): void {
		$stmt = $this->db->prepare('UPDATE credentials SET last_used_at = :now, last_status = \'ok\' WHERE id = :id');
		$stmt->execute(array(':now' => $now, ':id' => $id));
	}

	public function markFailed(string $id): void {
		$stmt = $this->db->prepare('UPDATE credentials SET last_status = \'auth_failed\' WHERE id = :id');
		$stmt->execute(array(':id' => $id));
	}

	/** Personal logins only, by their owner. */
	public function rename(VaultIdentity $who, string $id, string $label, string $access): void {
		$label = trim($label);
		$this->validateLabel($label);
		$this->validateAccess($access);
		$row = $this->manageable($who, $id);
		if ($row === null || $row['kind'] !== 'personal') {
			throw new VaultError('strvaultnotfound');
		}
		$stmt = $this->db->prepare('UPDATE credentials SET label = :label, access_label = :access, updated_at = :now WHERE id = :id');
		$stmt->execute(array(':label' => $label, ':access' => $access, ':now' => VaultStore::now(), ':id' => $id));
		$this->audit->log($who->username, VaultAudit::CREDENTIAL_CHANGED, array(
			'credential_id' => $id, 'server_id' => $row['server_id'], 'database' => $row['database'],
			'detail' => array('kind' => 'personal', 'access' => $access),
		));
	}

	/** Owner for a personal login, admin for a shared one. */
	public function updatePassword(VaultIdentity $who, string $id, string $password): void {
		$this->validatePassword($password);
		$row = $this->manageable($who, $id);
		if ($row === null) {
			throw new VaultError('strvaultnotfound');
		}
		list($cipher, $nonce, $version) = $this->crypto->encrypt($password,
			VaultCrypto::aad($row['id'], $row['server_id'], $row['pg_username']));
		$stmt = $this->db->prepare('UPDATE credentials SET password_enc = :enc, nonce = :nonce, key_version = :ver,
			last_status = \'ok\', updated_at = :now WHERE id = :id');
		$stmt->bindValue(':enc', $cipher, PDO::PARAM_LOB);
		$stmt->bindValue(':nonce', $nonce, PDO::PARAM_LOB);
		$stmt->bindValue(':ver', $version, PDO::PARAM_INT);
		$stmt->bindValue(':now', VaultStore::now());
		$stmt->bindValue(':id', $id);
		$stmt->execute();
		$this->audit->log($who->username, VaultAudit::PASSWORD_UPDATED, array(
			'credential_id' => $id, 'server_id' => $row['server_id'], 'database' => $row['database'],
			'detail' => array('kind' => $row['kind'], 'pg_username' => $row['pg_username']),
		));
	}

	/** Owner for a personal login, admin for a shared one. Its shares go with it. */
	public function delete(VaultIdentity $who, string $id): void {
		$row = $this->manageable($who, $id);
		if ($row === null) {
			throw new VaultError('strvaultnotfound');
		}
		$stmt = $this->db->prepare('DELETE FROM credentials WHERE id = :id');
		$stmt->execute(array(':id' => $id));
		$this->audit->log($who->username, VaultAudit::CREDENTIAL_DELETED, array(
			'credential_id' => $id, 'server_id' => $row['server_id'], 'database' => $row['database'],
			'detail' => array('kind' => $row['kind'], 'pg_username' => $row['pg_username']),
		));
	}

	/** This person's personal logins on active servers, by server then label. */
	public function mine(VaultIdentity $who): array {
		$stmt = $this->db->prepare('SELECT c.id, c.kind, c.label, c.server_id, c."database", c.pg_username, c.access_label,
				c.last_used_at, c.last_status, c.created_at
			FROM credentials c JOIN servers sv ON sv."key" = c.server_id AND sv.status = \'active\'
			WHERE c.kind = \'personal\' AND c.owner = :owner
			ORDER BY c.server_id, c.label, c.id');
		$stmt->execute(array(':owner' => $who->username));
		return $stmt->fetchAll(PDO::FETCH_ASSOC);
	}

	/** Shared logins this person can use anywhere, same row shape as listFor() plus server_id and database. */
	public function sharedWithMe(VaultIdentity $who, string $now): array {
		return $this->sharedRows($who, $now, '1 = 1', array(), false, true);
	}

	/**
	 * Gives a shared login to a user or a group (admins only). Sharing again
	 * with the same principal replaces the row, so it sets a new expiry.
	 * @param string $type 'user' or 'group'
	 * @param string|null $expiresDate 'Y-m-d' (today or later, UTC; the share
	 *   ends at the end of that day) or null for no expiry
	 * @throws VaultError on a bad principal, type or date, or a login that
	 *   isn't a shared one this admin may manage
	 */
	public function share(VaultIdentity $admin, string $id, string $type, string $principal, ?string $expiresDate): void {
		$principal = trim($principal);
		$this->validateShare($type, $principal);
		$expiresAt = null;
		if ($expiresDate !== null) {
			if (!preg_match('/^(\d{4})-(\d{2})-(\d{2})$/D', $expiresDate, $m) || !checkdate((int)$m[2], (int)$m[3], (int)$m[1])) {
				throw new VaultError('strvaultbadexpiry');
			}
			if ($expiresDate < gmdate('Y-m-d')) {
				throw new VaultError('strvaultexpirypast');
			}
			$expiresAt = $expiresDate . 'T23:59:59Z';
		}
		$row = $this->manageableShared($admin, $id);
		$stmt = $this->db->prepare('INSERT OR REPLACE INTO credential_shares
			(credential_id, principal_type, principal, expires_at, granted_by, granted_at)
			VALUES (:id, :type, :principal, :expires, :by, :now)');
		$stmt->execute(array(
			':id' => $id, ':type' => $type, ':principal' => $principal, ':expires' => $expiresAt,
			':by' => $admin->username, ':now' => VaultStore::now(),
		));
		$this->audit->log($admin->username, VaultAudit::SHARE_ADDED, array(
			'credential_id' => $id, 'server_id' => $row['server_id'], 'database' => $row['database'],
			'detail' => array('type' => $type, 'principal' => $principal, 'expires_at' => $expiresAt),
		));
	}

	/**
	 * Takes a share away (admins only). Access stops on the person's next
	 * request. A share that isn't there is left alone.
	 */
	public function unshare(VaultIdentity $admin, string $id, string $type, string $principal): void {
		if ($type !== 'user' && $type !== 'group') {
			throw new VaultError('strvaultbadsharetype');
		}
		$row = $this->manageableShared($admin, $id);
		$stmt = $this->db->prepare('DELETE FROM credential_shares
			WHERE credential_id = :id AND principal_type = :type AND principal = :principal');
		$stmt->execute(array(':id' => $id, ':type' => $type, ':principal' => $principal));
		if ($stmt->rowCount() === 0) {
			return;
		}
		$this->audit->log($admin->username, VaultAudit::SHARE_REMOVED, array(
			'credential_id' => $id, 'server_id' => $row['server_id'], 'database' => $row['database'],
			'detail' => array('type' => $type, 'principal' => $principal),
		));
	}

	/** The shares of one login, expired ones included: groups first, then users, by name. */
	public function shares(string $id): array {
		$stmt = $this->db->prepare('SELECT principal_type, principal, expires_at, granted_by, granted_at
			FROM credential_shares WHERE credential_id = :id ORDER BY principal_type, principal');
		$stmt->execute(array(':id' => $id));
		return $stmt->fetchAll(PDO::FETCH_ASSOC);
	}

	/**
	 * Every shared login, for the admin list, by server name then label,
	 * with its server's name, source and status and a summary of who has
	 * it ("2 groups, 1 user, expires 30 Nov"; "not shared yet"). Expired
	 * shares give no access, so they don't count. No password fields.
	 */
	public function sharedAll(): array {
		$now = VaultStore::now();
		$rows = $this->db->query('SELECT c.id, c.label, c.server_id, c."database", c.pg_username, c.access_label,
				c.last_used_at, c.last_status, c.owner, c.created_at,
				sv.name AS server_name, sv.source AS server_source, sv.status AS server_status
			FROM credentials c JOIN servers sv ON sv."key" = c.server_id
			WHERE c.kind = \'shared\'
			ORDER BY sv.name COLLATE NOCASE, sv."key", c.label COLLATE NOCASE, c.id')->fetchAll(PDO::FETCH_ASSOC);

		$counts = array();
		$stmt = $this->db->prepare('SELECT s.credential_id, s.principal_type, COUNT(*) AS n, MIN(s.expires_at) AS soonest
			FROM credential_shares s JOIN credentials c ON c.id = s.credential_id AND c.kind = \'shared\'
			WHERE s.expires_at IS NULL OR s.expires_at > :now
			GROUP BY s.credential_id, s.principal_type');
		$stmt->execute(array(':now' => $now));
		foreach ($stmt->fetchAll(PDO::FETCH_ASSOC) as $r) {
			$counts[$r['credential_id']][$r['principal_type']] = array((int)$r['n'], $r['soonest']);
		}

		$year = substr($now, 0, 4);
		foreach ($rows as &$row) {
			$c = isset($counts[$row['id']]) ? $counts[$row['id']] : array();
			$parts = array();
			$soonest = null;
			foreach (array('group' => array('strvaultonegroup', '1 group', 'strvaultngroups', '%d groups'),
					'user' => array('strvaultoneuser', '1 user', 'strvaultnusers', '%d users')) as $type => $words) {
				if (!isset($c[$type])) {
					continue;
				}
				list($n, $min) = $c[$type];
				$parts[] = $n === 1 ? self::text($words[0], $words[1]) : sprintf(self::text($words[2], $words[3]), $n);
				if ($min !== null && ($soonest === null || $min < $soonest)) {
					$soonest = $min;
				}
			}
			if (!$parts) {
				$row['summary'] = self::text('strvaultnotshared', 'not shared yet');
				continue;
			}
			$summary = implode(', ', $parts);
			if ($soonest !== null) {
				$ts = strtotime($soonest);
				$date = $ts === false ? $soonest : gmdate(substr($soonest, 0, 4) === $year ? 'j M' : 'j M Y', $ts);
				$summary .= sprintf(self::text('strvaultsummaryexpires', ', expires %s'), $date);
			}
			$row['summary'] = $summary;
		}
		unset($row);
		return $rows;
	}

	/** The group names shared logins are shared with, sorted (for the share form's suggestions). */
	public function groupPrincipals(): array {
		return $this->db->query('SELECT DISTINCT principal FROM credential_shares WHERE principal_type = \'group\'
			ORDER BY principal')->fetchAll(PDO::FETCH_COLUMN);
	}

	/**
	 * Checks a shared login's fields without writing: label, username,
	 * database and access tag are valid, the server is an active one, and a
	 * password is given when one is needed (always for a new login; for an
	 * existing one when the server, database or username changed, since the
	 * stored password was for the old ones).
	 * @param string|null $id the login being edited, null for a new one
	 * @throws VaultError
	 */
	public function checkShared(array $f, ?string $id = null): void {
		$label = trim((string)$f['label']);
		$password = (string)$f['password'];
		$this->validateLabel($label);
		$this->validateAccess((string)$f['access_label']);
		if (strlen((string)$f['pg_username']) < 1 || strlen((string)$f['pg_username']) > 63) {
			throw new VaultError('strvaultbadpguser');
		}
		if (strlen((string)$f['database']) < 1 || strlen((string)$f['database']) > 63) {
			throw new VaultError('strvaultbaddatabase');
		}
		$row = null;
		if ($id !== null) {
			$stmt = $this->db->prepare('SELECT * FROM credentials WHERE id = :id AND kind = \'shared\'');
			$stmt->execute(array(':id' => $id));
			$row = $stmt->fetch(PDO::FETCH_ASSOC);
			if ($row === false) {
				throw new VaultError('strvaultnotfound');
			}
		}
		$moved = $row === null || $row['server_id'] !== (string)$f['server_id'];
		if ($moved) {
			$stmt = $this->db->prepare('SELECT 1 FROM servers WHERE "key" = :k AND status = \'active\'');
			$stmt->execute(array(':k' => (string)$f['server_id']));
			if ($stmt->fetchColumn() === false) {
				throw new VaultError('strvaultservernotfound');
			}
		}
		if ($password === '') {
			if ($row === null) {
				throw new VaultError('strvaultbadpassword');
			}
			if ($moved || $row['database'] !== (string)$f['database'] || $row['pg_username'] !== (string)$f['pg_username']) {
				throw new VaultError('strvaultneedpassword');
			}
		} else {
			$this->validatePassword($password);
		}
	}

	/**
	 * The stored password of a shared login, for the connection test of the
	 * edit form. Server side only: it is never shown. Admins only.
	 * @throws VaultError when not a shared login or it can't be decrypted
	 */
	public function sharedPassword(VaultIdentity $admin, string $id): string {
		return $this->password($this->manageableShared($admin, $id));
	}

	/**
	 * Adds a shared login (admins only); the caller has tested the
	 * connection. Not visible to anyone until it is shared.
	 * @param array $f server_id, database, pg_username, password, label, access_label
	 * @return string the new credential's id
	 */
	public function saveShared(VaultIdentity $admin, array $f): string {
		if (!$admin->isAdmin) {
			throw new VaultError('strvaultnotfound');
		}
		$this->checkShared($f);
		$id = VaultStore::uuid();
		$serverKey = (string)$f['server_id'];
		$pgUser = (string)$f['pg_username'];
		list($cipher, $nonce, $version) = $this->crypto->encrypt((string)$f['password'], VaultCrypto::aad($id, $serverKey, $pgUser));
		$now = VaultStore::now();
		$stmt = $this->db->prepare('INSERT INTO credentials
			(id, kind, owner, label, server_id, "database", pg_username, password_enc, nonce, key_version, access_label, created_at, updated_at)
			VALUES (:id, \'shared\', :owner, :label, :server, :database, :pg, :enc, :nonce, :ver, :access, :now, :now)');
		$stmt->bindValue(':id', $id);
		$stmt->bindValue(':owner', $admin->username);
		$stmt->bindValue(':label', trim((string)$f['label']));
		$stmt->bindValue(':server', $serverKey);
		$stmt->bindValue(':database', (string)$f['database']);
		$stmt->bindValue(':pg', $pgUser);
		$stmt->bindValue(':enc', $cipher, PDO::PARAM_LOB);
		$stmt->bindValue(':nonce', $nonce, PDO::PARAM_LOB);
		$stmt->bindValue(':ver', $version, PDO::PARAM_INT);
		$stmt->bindValue(':access', (string)$f['access_label']);
		$stmt->bindValue(':now', $now);
		$stmt->execute();
		$this->audit->log($admin->username, VaultAudit::LOGIN_SAVED, array(
			'credential_id' => $id, 'server_id' => $serverKey, 'database' => (string)$f['database'],
			'detail' => array('kind' => 'shared'),
		));
		return $id;
	}

	/**
	 * Edits a shared login (admins only); the caller has tested the
	 * connection. An empty password keeps the current one, unless the
	 * server, database or username changed. The password is encrypted again
	 * whenever it or the server or username changes, so the ciphertext is
	 * always bound to the row's current server and username.
	 * @throws VaultError('strvaultneedpassword')
	 */
	public function updateShared(VaultIdentity $admin, string $id, array $f): void {
		$row = $this->manageableShared($admin, $id);
		$this->checkShared($f, $id);
		$serverKey = (string)$f['server_id'];
		$pgUser = (string)$f['pg_username'];
		$password = (string)$f['password'];
		$sets = 'server_id = :server, "database" = :database, pg_username = :pg, label = :label, access_label = :access, updated_at = :now';
		$replaced = $password !== '';
		if ($replaced) {
			list($cipher, $nonce, $version) = $this->crypto->encrypt($password, VaultCrypto::aad($id, $serverKey, $pgUser));
			$sets .= ', password_enc = :enc, nonce = :nonce, key_version = :ver, last_status = \'ok\'';
		}
		$stmt = $this->db->prepare('UPDATE credentials SET ' . $sets . ' WHERE id = :id');
		$stmt->bindValue(':server', $serverKey);
		$stmt->bindValue(':database', (string)$f['database']);
		$stmt->bindValue(':pg', $pgUser);
		$stmt->bindValue(':label', trim((string)$f['label']));
		$stmt->bindValue(':access', (string)$f['access_label']);
		$stmt->bindValue(':now', VaultStore::now());
		$stmt->bindValue(':id', $id);
		if ($replaced) {
			$stmt->bindValue(':enc', $cipher, PDO::PARAM_LOB);
			$stmt->bindValue(':nonce', $nonce, PDO::PARAM_LOB);
			$stmt->bindValue(':ver', $version, PDO::PARAM_INT);
		}
		$stmt->execute();
		$detail = array('kind' => 'shared', 'pg_username' => $pgUser);
		$this->audit->log($admin->username, VaultAudit::CREDENTIAL_CHANGED, array(
			'credential_id' => $id, 'server_id' => $serverKey, 'database' => (string)$f['database'], 'detail' => $detail,
		));
		if ($replaced) {
			$this->audit->log($admin->username, VaultAudit::PASSWORD_UPDATED, array(
				'credential_id' => $id, 'server_id' => $serverKey, 'database' => (string)$f['database'], 'detail' => $detail,
			));
		}
	}

	/** A shared login this admin may share; VaultError('strvaultnotfound') otherwise. */
	private function manageableShared(VaultIdentity $admin, string $id): array {
		$row = $this->manageable($admin, $id);
		if ($row === null || $row['kind'] !== 'shared') {
			throw new VaultError('strvaultnotfound');
		}
		return $row;
	}

	private function validateShare(string $type, string $principal): void {
		if ($type !== 'user' && $type !== 'group') {
			throw new VaultError('strvaultbadsharetype');
		}
		if (!preg_match('/^[^\p{Cc}]{1,128}$/Dsu', $principal)) {
			throw new VaultError('strvaultbadprincipal');
		}
	}

	private static function text(string $key, string $fallback): string {
		global $lang;
		return isset($lang[$key]) ? $lang[$key] : $fallback;
	}

	/**
	 * The row if $who may edit or delete it: owner for personal, admin for
	 * shared. Any server status: managing doesn't connect.
	 */
	private function manageable(VaultIdentity $who, string $id): ?array {
		$stmt = $this->db->prepare('SELECT * FROM credentials WHERE id = :id');
		$stmt->execute(array(':id' => $id));
		$row = $stmt->fetch(PDO::FETCH_ASSOC);
		if ($row === false) {
			return null;
		}
		if ($row['kind'] === 'personal') {
			return $row['owner'] === $who->username ? $row : null;
		}
		return $who->isAdmin ? $row : null;
	}

	/**
	 * Shared logins on active servers that have an unexpired share for this
	 * person or one of their groups. One entry per credential: via is 'you'
	 * for a direct share, else the alphabetically first matching group;
	 * expires_at is null if any matching share never expires, else the latest.
	 */
	private function sharedRows(VaultIdentity $who, string $now, string $where, array $params, bool $full, bool $withScope = false): array {
		$match = '(s.principal_type = \'user\' AND s.principal = :who)';
		$bind = array_merge($params, array(':now' => $now, ':who' => $who->username));
		$i = 0;
		$marks = array();
		foreach ($who->groups as $g) {
			$marks[] = ':g' . $i;
			$bind[':g' . $i] = $g;
			$i++;
		}
		if ($marks) {
			$match .= ' OR (s.principal_type = \'group\' AND s.principal IN (' . implode(', ', $marks) . '))';
		}
		$cols = $full ? 'c.*' : 'c.id, c.kind, c.label, c.pg_username, c.access_label, c.last_used_at, c.last_status'
			. ($withScope ? ', c.server_id, c."database"' : '');
		$stmt = $this->db->prepare('SELECT ' . $cols . ', s.principal_type AS share_type, s.principal AS share_principal, s.expires_at AS share_expires
			FROM credentials c
			JOIN servers sv ON sv."key" = c.server_id AND sv.status = \'active\'
			JOIN credential_shares s ON s.credential_id = c.id
			WHERE c.kind = \'shared\' AND (' . $match . ') AND (s.expires_at IS NULL OR s.expires_at > :now) AND ' . $where);
		$stmt->execute($bind);

		$byId = array();
		foreach ($stmt->fetchAll(PDO::FETCH_ASSOC) as $r) {
			$id = $r['id'];
			$via = $r['share_type'] === 'user' ? 'you' : 'group:' . $r['share_principal'];
			$exp = $r['share_expires'];
			unset($r['share_type'], $r['share_principal'], $r['share_expires']);
			if (!isset($byId[$id])) {
				$r['via'] = $via;
				$r['expires_at'] = $exp;
				$byId[$id] = $r;
				continue;
			}
			$cur = $byId[$id];
			if ($cur['expires_at'] !== null && ($exp === null || $exp > $cur['expires_at'])) {
				$byId[$id]['expires_at'] = $exp;
			}
			if ($cur['via'] !== 'you' && ($via === 'you' || strcmp($via, $cur['via']) < 0)) {
				$byId[$id]['via'] = $via;
			}
		}
		$rows = array_values($byId);
		usort($rows, function ($a, $b) use ($withScope) {
			if ($withScope && $a['server_id'] !== $b['server_id']) {
				return strcmp($a['server_id'], $b['server_id']);
			}
			$c = strcmp($a['label'], $b['label']);
			return $c !== 0 ? $c : strcmp($a['id'], $b['id']);
		});
		return $rows;
	}

	private function validate(string $label, string $pgUser, string $database, string $password, string $access): void {
		$this->validateLabel($label);
		if (strlen($pgUser) < 1 || strlen($pgUser) > 63) {
			throw new VaultError('strvaultbadpguser');
		}
		if (strlen($database) < 1 || strlen($database) > 63) {
			throw new VaultError('strvaultbaddatabase');
		}
		$this->validatePassword($password);
		$this->validateAccess($access);
	}

	private function validateLabel(string $label): void {
		if (!preg_match('/^[^\p{Cc}]{1,100}$/Dsu', $label)) {
			throw new VaultError('strvaultbadlabel');
		}
	}

	private function validatePassword(string $password): void {
		if (strlen($password) < 1 || strlen($password) > 1000) {
			throw new VaultError('strvaultbadpassword');
		}
	}

	private function validateAccess(string $access): void {
		if ($access !== 'read-only' && $access !== 'read-write') {
			throw new VaultError('strvaultbadaccess');
		}
	}
}

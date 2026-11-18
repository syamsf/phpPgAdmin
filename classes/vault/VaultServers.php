<?php

require_once(__DIR__ . '/VaultError.php');
require_once(__DIR__ . '/VaultStore.php');
require_once(__DIR__ . '/VaultAudit.php');

/**
 * The servers table. Servers from the config (PPA_SERVERS) are mirrored into
 * it with stable keys, so saved logins can point at them. Servers added in
 * the UI live only here and are appended to $conf['servers'] on each request.
 */
class VaultServers {

	/** The columns compared to decide whether an env row needs a write. */
	private const SYNCED = array('name', 'host', 'port', 'sslmode', 'default_db', 'pgbouncer', 'source', 'status');

	private $db;
	private $audit;

	public function __construct(PDO $db, VaultAudit $audit) {
		$this->db = $db;
		$this->audit = $audit;
	}

	/** Lowercase, runs of anything but a-z0-9 become "-", trimmed, at most 63 bytes. */
	public static function slug(string $desc): string {
		$slug = trim(preg_replace('/[^a-z0-9]+/', '-', strtolower($desc)), '-');
		$slug = trim(substr($slug, 0, 63), '-');
		return $slug === '' ? 'server' : $slug;
	}

	/**
	 * Config index => key. A repeated slug gets -2, -3... in config order.
	 * Only env servers collide with each other: a UI row with the same key is
	 * taken over by syncEnv(), not avoided.
	 */
	public static function envKeys(array $confServers): array {
		$keys = array();
		$used = array();
		foreach ($confServers as $i => $server) {
			$base = self::slug(isset($server['desc']) ? (string)$server['desc'] : '');
			$key = $base;
			for ($n = 2; isset($used[$key]); $n++) {
				$suffix = '-' . $n;
				$key = trim(substr($base, 0, 63 - strlen($suffix)), '-') . $suffix;
			}
			$used[$key] = true;
			$keys[$i] = $key;
		}
		return $keys;
	}

	/**
	 * Makes the table agree with the config: each env server is upserted as
	 * active, env rows no longer in the config become removed (their logins
	 * stay, hidden), and a UI row with an env key becomes an env row.
	 * Writes only the rows that differ. The check is read-only, so the usual
	 * request takes no lock; when there is work, it is redone inside a write
	 * transaction in case a parallel request did it first.
	 */
	public function syncEnv(array $confServers, string $now): void {
		if (!$this->plan($confServers)) {
			return;
		}
		$this->transaction(function () use ($confServers, $now) {
			foreach ($this->plan($confServers) as $step) {
				$this->apply($step, $now);
			}
		});
	}

	/** The writes syncEnv would make right now, as a list of steps. */
	private function plan(array $confServers): array {
		$keys = self::envKeys($confServers);
		$steps = array();
		$seen = array();
		foreach ($confServers as $i => $server) {
			$key = $keys[$i];
			$seen[$key] = true;
			$want = array(
				'name' => isset($server['desc']) ? (string)$server['desc'] : '',
				'host' => (string)($server['host'] ?? ''),
				'port' => (int)($server['port'] ?? 5432),
				'sslmode' => (string)($server['sslmode'] ?? ''),
				'default_db' => (string)($server['defaultdb'] ?? 'postgres'),
				'pgbouncer' => empty($server['pgbouncer']) ? 0 : 1,
				'source' => 'env',
				'status' => 'active',
			);
			$row = $this->get($key);
			if ($row === null) {
				$steps[] = array('insert', $key, $want, null);
			} elseif ($this->differs($row, $want)) {
				$steps[] = array('update', $key, $want, $row['source']);
			}
		}
		$stmt = $this->db->query("SELECT \"key\" FROM servers WHERE source = 'env' AND status <> 'removed'");
		foreach ($stmt->fetchAll(PDO::FETCH_COLUMN) as $key) {
			if (!isset($seen[$key])) {
				$steps[] = array('remove', (string)$key, array(), null);
			}
		}
		return $steps;
	}

	private function apply(array $step, string $now): void {
		list($op, $key, $want, $was) = $step;
		if ($op === 'insert') {
			$this->db->prepare('INSERT INTO servers ("key", name, source, host, port, sslmode, default_db, pgbouncer, status, created_by, created_at, updated_at)
				VALUES (:key, :name, :source, :host, :port, :sslmode, :default_db, :pgbouncer, :status, NULL, :now, :now)')
				->execute(array(':key' => $key, ':now' => $now) + $this->named($want));
		} elseif ($op === 'update') {
			$this->db->prepare('UPDATE servers SET name = :name, host = :host, port = :port, sslmode = :sslmode,
				default_db = :default_db, pgbouncer = :pgbouncer, source = :source, status = :status, updated_at = :now WHERE "key" = :key')
				->execute(array(':key' => $key, ':now' => $now) + $this->named($want));
			if ($was === 'ui') {
				$this->audit->log('system', VaultAudit::SERVER_CHANGED, array(
					'server_id' => $key,
					'detail' => array('reason' => 'env took over key'),
				));
			}
		} else {
			$this->db->prepare("UPDATE servers SET status = 'removed', updated_at = :now WHERE \"key\" = :key")
				->execute(array(':key' => $key, ':now' => $now));
		}
	}

	/**
	 * The $conf['servers'] list for this request: the env entries as given,
	 * at their own indexes, with 'key' and 'source' => 'env'; then each
	 * active UI server, appended after the highest index. With $withUi
	 * false (SERVERS_ALLOW_UI=false) the UI servers are left out: they
	 * leave the tree and their logins stop working, but their rows stay.
	 */
	public function confServers(array $confServers, array $uiDefaults, bool $withUi = true): array {
		$keys = self::envKeys($confServers);
		$out = array();
		foreach ($confServers as $i => $server) {
			$out[$i] = $server + array('key' => $keys[$i], 'source' => 'env');
		}
		if (!$withUi) {
			return $out;
		}
		$stmt = $this->db->query("SELECT * FROM servers WHERE source = 'ui' AND status = 'active' ORDER BY created_at, \"key\"");
		foreach ($stmt->fetchAll(PDO::FETCH_ASSOC) as $row) {
			$next = $out ? max(array_keys($out)) + 1 : 0;
			$out[$next] = array(
				'desc' => $row['name'],
				'host' => $row['host'],
				'port' => (int)$row['port'],
				'sslmode' => $row['sslmode'] ?: 'prefer',
				'defaultdb' => $row['default_db'],
				'pgbouncer' => (bool)$row['pgbouncer'],
				'key' => $row['key'],
				'source' => 'ui',
			) + $uiDefaults;
		}
		return $out;
	}

	/** The active servers (env and UI) as vault rows, by name. */
	public function active(): array {
		return $this->db->query('SELECT * FROM servers WHERE status = \'active\' ORDER BY name COLLATE NOCASE, "key"')
			->fetchAll(PDO::FETCH_ASSOC);
	}

	public function get(string $key): ?array {
		$stmt = $this->db->prepare('SELECT * FROM servers WHERE "key" = :key');
		$stmt->execute(array(':key' => $key));
		$row = $stmt->fetch(PDO::FETCH_ASSOC);
		return $row === false ? null : $row;
	}

	/** The sslmodes a UI server may use (the spec's list). */
	const SSLMODES = array('disable', 'prefer', 'require', 'verify-full');

	/**
	 * Every server, env first then by key, with how many personal and
	 * shared logins each holds (counts only: no label or owner).
	 */
	public function listWithCounts(): array {
		return $this->db->query('SELECT s.*,
				(SELECT COUNT(*) FROM credentials c WHERE c.server_id = s."key" AND c.kind = \'personal\') AS personal_count,
				(SELECT COUNT(*) FROM credentials c WHERE c.server_id = s."key" AND c.kind = \'shared\') AS shared_count
			FROM servers s ORDER BY (s.source = \'env\') DESC, s."key"')->fetchAll(PDO::FETCH_ASSOC);
	}

	/**
	 * What deleting a server would remove: personal logins and their
	 * distinct owners, shared logins and the principals they are shared
	 * with, as [type, principal] pairs.
	 * @return array personal, owners, shared, principals
	 */
	public function impact(string $key): array {
		$stmt = $this->db->prepare('SELECT COUNT(*) AS n, COUNT(DISTINCT owner) AS owners FROM credentials WHERE server_id = :k AND kind = \'personal\'');
		$stmt->execute(array(':k' => $key));
		$personal = $stmt->fetch(PDO::FETCH_ASSOC);
		$stmt = $this->db->prepare('SELECT COUNT(*) FROM credentials WHERE server_id = :k AND kind = \'shared\'');
		$stmt->execute(array(':k' => $key));
		$shared = (int)$stmt->fetchColumn();
		$stmt = $this->db->prepare('SELECT DISTINCT sh.principal_type, sh.principal FROM credential_shares sh
			JOIN credentials c ON c.id = sh.credential_id WHERE c.server_id = :k AND c.kind = \'shared\'
			ORDER BY sh.principal_type, sh.principal');
		$stmt->execute(array(':k' => $key));
		$principals = array();
		foreach ($stmt->fetchAll(PDO::FETCH_NUM) as $row) {
			$principals[] = array((string)$row[0], (string)$row[1]);
		}
		return array('personal' => (int)$personal['n'], 'owners' => (int)$personal['owners'],
			'shared' => $shared, 'principals' => $principals);
	}

	/**
	 * Adds a UI server.
	 * @param array $f key, name, host, port, sslmode, default_db, pgbouncer, enabled
	 * @throws VaultError a field is wrong, the key is taken or the host:port:sslmode is in use
	 */
	public function add(array $f, string $actor): void {
		$f = $this->clean($f);
		if (!preg_match('/^[a-z0-9][a-z0-9-]{0,62}$/D', $f['key'])) {
			throw new VaultError('strvaultbadserverkey');
		}
		$this->transaction(function () use ($f, $actor) {
			if ($this->get($f['key']) !== null) {
				throw new VaultError('strvaultserverkeytaken');
			}
			$this->checkUnique($f, null);
			$now = VaultStore::now();
			$this->db->prepare('INSERT INTO servers ("key", name, source, host, port, sslmode, default_db, pgbouncer, status, created_by, created_at, updated_at)
				VALUES (:key, :name, \'ui\', :host, :port, :sslmode, :default_db, :pgbouncer, :status, :actor, :now, :now)')
				->execute(array(':key' => $f['key'], ':name' => $f['name'], ':host' => $f['host'], ':port' => $f['port'],
					':sslmode' => $f['sslmode'], ':default_db' => $f['default_db'], ':pgbouncer' => $f['pgbouncer'],
					':status' => $f['enabled'] ? 'active' : 'disabled', ':actor' => $actor, ':now' => $now));
			$this->audit->log($actor, VaultAudit::SERVER_ADDED, array('server_id' => $f['key'], 'detail' => array(
				'name' => $f['name'], 'host' => $f['host'], 'port' => $f['port'], 'sslmode' => $f['sslmode'],
				'default_db' => $f['default_db'], 'pgbouncer' => (bool)$f['pgbouncer'], 'enabled' => $f['enabled'])));
		});
	}

	/**
	 * Changes a UI server. The key is the row's and can't change. While the
	 * server holds saved or shared logins its host and port can't change and
	 * its SSL mode can only get stricter: the stored passwords would
	 * otherwise be sent to wherever the server now points.
	 * @throws VaultError the row is an env row, is gone, or a field is wrong
	 */
	public function update(string $key, array $f, string $actor): void {
		$f = $this->clean($f);
		$this->transaction(function () use ($key, $f, $actor) {
			$row = $this->uiRow($key);
			if ($this->retargets($row, $f) && $this->loginCount($key) > 0) {
				throw new VaultError('strvaultserverhaslogins');
			}
			$status = $f['enabled'] ? 'active' : 'disabled';
			if ($status === 'active') {
				$this->checkUnique($f, $key);
			}
			$changed = array();
			foreach (array('name', 'host', 'port', 'sslmode', 'default_db', 'pgbouncer', 'status') as $col) {
				$new = $col === 'status' ? $status : $f[$col];
				if ((string)$row[$col] !== (string)$new) {
					$changed[$col] = array('from' => $row[$col], 'to' => $new);
				}
			}
			if (!$changed) {
				return;
			}
			$this->db->prepare('UPDATE servers SET name = :name, host = :host, port = :port, sslmode = :sslmode,
				default_db = :default_db, pgbouncer = :pgbouncer, status = :status, updated_at = :now WHERE "key" = :key')
				->execute(array(':key' => $key, ':name' => $f['name'], ':host' => $f['host'], ':port' => $f['port'],
					':sslmode' => $f['sslmode'], ':default_db' => $f['default_db'], ':pgbouncer' => $f['pgbouncer'], ':status' => $status,
					':now' => VaultStore::now()));
			$this->audit->log($actor, VaultAudit::SERVER_CHANGED, array('server_id' => $key, 'detail' => array('changed' => $changed)));
		});
	}

	/** SSL modes from weakest to strictest. */
	const SSL_STRENGTH = array('disable' => 0, 'prefer' => 1, 'require' => 2, 'verify-full' => 3);

	/**
	 * True when $f points the server somewhere else: another host or port,
	 * or a weaker SSL mode (an unknown current mode counts as any change).
	 */
	private function retargets(array $row, array $f): bool {
		if (strcasecmp((string)$row['host'], (string)$f['host']) !== 0 || (int)$row['port'] !== (int)$f['port']) {
			return true;
		}
		$old = (string)$row['sslmode'];
		if ($old === $f['sslmode']) {
			return false;
		}
		if (!isset(self::SSL_STRENGTH[$old])) {
			return true;
		}
		return self::SSL_STRENGTH[$f['sslmode']] < self::SSL_STRENGTH[$old];
	}

	/** How many saved logins (personal and shared) are on the server. */
	private function loginCount(string $key): int {
		$stmt = $this->db->prepare('SELECT COUNT(*) FROM credentials WHERE server_id = :k');
		$stmt->execute(array(':k' => $key));
		return (int)$stmt->fetchColumn();
	}

	/** Enables ('active') or disables a UI server. */
	public function setStatus(string $key, string $status, string $actor): void {
		if (!in_array($status, array('active', 'disabled'), true)) {
			throw new VaultError('strvaultbadserverstatus');
		}
		$this->transaction(function () use ($key, $status, $actor) {
			$row = $this->uiRow($key);
			if ($row['status'] === $status) {
				return;
			}
			if ($status === 'active') {
				$this->checkUnique($row, $key);
			}
			$this->db->prepare('UPDATE servers SET status = :status, updated_at = :now WHERE "key" = :key')
				->execute(array(':key' => $key, ':status' => $status, ':now' => VaultStore::now()));
			$this->audit->log($actor, VaultAudit::SERVER_CHANGED, array('server_id' => $key, 'detail' => array(
				'changed' => array('status' => array('from' => $row['status'], 'to' => $status)))));
		});
	}

	/**
	 * Deletes a UI server, or an env server that was removed from the
	 * env, with every login on it. One audit row per login first.
	 * @return array personal and shared: how many logins went
	 */
	public function delete(string $key, string $actor): array {
		$counts = array('personal' => 0, 'shared' => 0);
		$this->transaction(function () use ($key, $actor, &$counts) {
			$row = $this->get($key);
			if ($row === null) {
				throw new VaultError('strvaultservernotfound');
			}
			if ($row['source'] === 'env' && $row['status'] !== 'removed') {
				throw new VaultError('strvaultenvreadonly');
			}
			$stmt = $this->db->prepare('SELECT id, kind, "database" FROM credentials WHERE server_id = :k');
			$stmt->execute(array(':k' => $key));
			foreach ($stmt->fetchAll(PDO::FETCH_ASSOC) as $cred) {
				$counts[$cred['kind']]++;
				$this->audit->log($actor, VaultAudit::CREDENTIAL_DELETED, array(
					'credential_id' => $cred['id'], 'server_id' => $key, 'database' => $cred['database'],
					'detail' => array('reason' => 'server_deleted')));
			}
			$this->db->prepare('DELETE FROM servers WHERE "key" = :k')->execute(array(':k' => $key));
			$this->audit->log($actor, VaultAudit::SERVER_DELETED, array('server_id' => $key, 'detail' => array(
				'name' => $row['name'], 'source' => $row['source'], 'personal' => $counts['personal'], 'shared' => $counts['shared'])));
		});
		return $counts;
	}

	/** The row of a UI server. @throws VaultError missing, or an env row */
	private function uiRow(string $key): array {
		$row = $this->get($key);
		if ($row === null) {
			throw new VaultError('strvaultservernotfound');
		}
		if ($row['source'] !== 'ui') {
			throw new VaultError('strvaultenvreadonly');
		}
		return $row;
	}

	/**
	 * Trims and checks the form fields (not the key); returns them typed.
	 * @throws VaultError a field is wrong
	 */
	public function clean(array $f): array {
		$out = array(
			'key' => isset($f['key']) ? trim((string)$f['key']) : '',
			'name' => isset($f['name']) ? trim((string)$f['name']) : '',
			'host' => isset($f['host']) ? trim((string)$f['host']) : '',
			'port' => isset($f['port']) ? trim((string)$f['port']) : '',
			'sslmode' => isset($f['sslmode']) ? (string)$f['sslmode'] : '',
			'default_db' => isset($f['default_db']) ? trim((string)$f['default_db']) : '',
			'pgbouncer' => empty($f['pgbouncer']) ? 0 : 1,
			'enabled' => !empty($f['enabled']),
		);
		if (!preg_match('/^[^\p{Cc}]{1,100}$/Dsu', $out['name'])) {
			throw new VaultError('strvaultbadservername');
		}
		if (!preg_match('/^[^\s\p{Cc}]{1,253}$/Dsu', $out['host'])) {
			throw new VaultError('strvaultbadhost');
		}
		if (!preg_match('/^[0-9]{1,5}$/D', $out['port']) || (int)$out['port'] < 1 || (int)$out['port'] > 65535) {
			throw new VaultError('strvaultbadport');
		}
		$out['port'] = (int)$out['port'];
		if (!in_array($out['sslmode'], self::SSLMODES, true)) {
			throw new VaultError('strvaultbadsslmode');
		}
		if ($out['default_db'] === '' || strlen($out['default_db']) > 63 || preg_match('/\p{Cc}/u', $out['default_db'])) {
			throw new VaultError('strvaultbaddatabase');
		}
		return $out;
	}

	/**
	 * No other active server may share host:port:sslmode: the session
	 * server id would be the same.
	 * @param ?string $except the key of the row being changed
	 */
	private function checkUnique(array $f, ?string $except): void {
		$stmt = $this->db->prepare('SELECT "key", name FROM servers WHERE status = \'active\' AND "key" <> :except
			AND lower(host) = lower(:host) AND port = :port AND sslmode = :sslmode ORDER BY "key" LIMIT 1');
		$stmt->execute(array(':except' => (string)$except, ':host' => $f['host'], ':port' => (int)$f['port'], ':sslmode' => $f['sslmode']));
		$other = $stmt->fetch(PDO::FETCH_ASSOC);
		if ($other !== false) {
			global $lang;
			$text = isset($lang['strvaultserverduplicate']) ? $lang['strvaultserverduplicate']
				: '%s already uses this host, port and SSL mode.';
			throw new VaultError(sprintf($text, $other['name']));
		}
	}

	/**
	 * Runs $fn in a write transaction; rolls back on any exception. See
	 * VaultStore::transaction(): PHP < 8.4's inTransaction() doesn't see a
	 * BEGIN sent through exec(), so the rollback is unconditional.
	 */
	private function transaction(callable $fn): void {
		VaultStore::transaction($this->db, $fn);
	}

	private function differs(array $row, array $want): bool {
		foreach (self::SYNCED as $col) {
			if ((string)$row[$col] !== (string)$want[$col]) {
				return true;
			}
		}
		return false;
	}

	private function named(array $want): array {
		$out = array();
		foreach ($want as $col => $value) {
			$out[':' . $col] = $value;
		}
		return $out;
	}
}

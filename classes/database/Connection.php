<?php

/**
 * Class to represent a database connection
 *
 * $Id: Connection.php,v 1.15 2008/02/18 21:42:47 ioguix Exp $
 */

include_once('./classes/database/ADODB_base.php');

class Connection {

	public $conn;

	// The backend platform.  Set to UNKNOWN by default.
	public $platform = 'UNKNOWN';

	/**
	 * Creates a new connection.  Will actually make a database connection.
	 * @param $fetchMode Defaults to associative.  Override for different behaviour
	 */
	function __construct($host, $port, $sslmode, $user, $password, $database, $fetchMode = ADODB_FETCH_ASSOC, $sslrootcert = '') {
		$this->conn = ADONewConnection('postgres');
		$this->conn->setFetchMode($fetchMode);

		// Hand the driver a complete pg_connect() connection string. This
		// calls the driver's _connect() directly, not ADOdb's Connect(): that
		// runs parse_url() over its first argument, which would let text in
		// the password or database name replace the whole string. Going
		// through its "host:port" form would also drop the sslmode and mangle
		// IPv6 hosts.
		$adodb = $this->conn;
		$ok = false;
		if (!self::validSslmode($sslmode)) {
			$err = 'Invalid sslmode "' . $sslmode . '": use unspecified, disable, allow, prefer, require, verify-ca or verify-full';
			$errno = 0;
		} else {
			// @: ADODB calls pg_connect() unsuppressed and a failed login would log a
			// PHP Warning; error_get_last() still holds the message (see errorhandler).
			$ok = @$adodb->_connect(self::conninfo($host, $port, $sslmode, $user, $password, $database, $sslrootcert));
			if (isset($ok)) {
				$err = $adodb->ErrorMsg();
				$errno = $adodb->ErrorNo();
				if (empty($err))
					$err = 'Connection error to server';
			} else {
				$err = 'Missing extension for ' . $adodb->dataProvider;
				$errno = 0;
			}
		}
		if (!$ok) {
			if ($fn = $adodb->raiseErrorFn)
				$fn($adodb->databaseType, 'CONNECT', $errno, $err, '', '', $adodb);
			$adodb->_connectionID = false;
		}
	}

	/**
	 * sslmode values we pass on; '' and 'unspecified' mean "send none".
	 */
	static function validSslmode($sslmode) {
		return $sslmode === null || in_array($sslmode, array('', 'unspecified', 'disable', 'allow', 'prefer',
			'require', 'verify-ca', 'verify-full'), true);
	}

	/**
	 * The sslmode to give libpq or pg_dump: the mode itself, or null when
	 * none is to be sent ('', 'unspecified') or it is not a real mode.
	 */
	static function sslmodeForLibpq($sslmode) {
		if ($sslmode === null || in_array($sslmode, array('', 'unspecified'), true) || !self::validSslmode($sslmode))
			return null;
		return $sslmode;
	}

	/**
	 * Quotes a value for a libpq connection string.
	 */
	static function conninfoValue($value) {
		return "'" . addcslashes((string) $value, "'\\") . "'";
	}

	/**
	 * Builds a libpq connection string. Check the sslmode with validSslmode() first.
	 */
	static function conninfo($host, $port, $sslmode, $user, $password, $database, $sslrootcert = '') {
		$params = array();
		if ($host !== null && $host !== '')
			$params['host'] = $host;
		if ($port !== null && $port !== '')
			$params['port'] = $port;
		if (self::sslmodeForLibpq($sslmode) !== null)
			$params['sslmode'] = $sslmode;
		if ($sslrootcert !== null && $sslrootcert !== '')
			$params['sslrootcert'] = $sslrootcert;
		$params['user'] = $user;
		$params['password'] = $password;
		// As ADOdb did: without a database name, libpq would use the user name.
		$params['dbname'] = ($database !== null && $database !== '') ? $database : 'template1';

		$str = '';
		foreach ($params as $name => $value)
			$str .= $name . '=' . self::conninfoValue($value) . ' ';
		return rtrim($str);
	}

	/**
	 * Gets the name of the correct database driver to use.  As a side effect,
	 * sets the platform.
	 * @param (return-by-ref) $description A description of the database and version
	 * @return The class name of the driver eg. Postgres84
	 * @return null if version is < 7.4
	 * @return -3 Database-specific failure
	 */
	function getDriver(&$description) {
		$v = pg_version($this->conn->_connectionID);
		if (isset($v['server'])) $version = $v['server'];

		// If we didn't manage to get the version without a query, query...
		if (!isset($version)) {
			$adodb = new ADODB_base($this->conn);

			$sql = "SELECT VERSION() AS version";
			$field = $adodb->selectField($sql, 'version');

			// Check the platform, if it's mingw, set it
			if (preg_match('/ mingw /i', $field))
				$this->platform = 'MINGW';

			$params = explode(' ', $field);
			if (!isset($params[1])) return -3;

			$version = $params[1]; // eg. 8.4.4
		}

		$description = "PostgreSQL {$version}";

		// Detect version and choose appropriate database driver
		switch (substr($version,0,2)) {
			case '14': return 'Postgres'; break;
			case '13': return 'Postgres13'; break;
			case '12': return 'Postgres12'; break;
			case '11': return 'Postgres11'; break;
			case '10': return 'Postgres10'; break;
		}

		switch (substr($version,0,3)) {
			case '9.6': return 'Postgres96'; break;
			case '9.5': return 'Postgres95'; break;
			case '9.4': return 'Postgres94'; break;
			case '9.3': return 'Postgres93'; break;
			case '9.2': return 'Postgres92'; break;
			case '9.1': return 'Postgres91'; break;
			case '9.0': return 'Postgres90'; break;
			case '8.4': return 'Postgres84'; break;
			case '8.3': return 'Postgres83'; break;
			case '8.2': return 'Postgres82'; break;
			case '8.1': return 'Postgres81'; break;
			case '8.0':
			case '7.5': return 'Postgres80'; break;
			case '7.4': return 'Postgres74'; break;
		}

		/* All <7.4 versions are not supported */
		// if major version is 7 or less and wasn't caught in the
		// switch/case block, we have an unsupported version.
		$floatVer = floatval(explode(' ', $version)[0]);
		if ($floatVer < 7.4) {
			return null;
		}

		// If unknown version, then default to latest driver
		return 'Postgres';
	}

	/**
	 * Get the last error in the connection
	 * @return Error string
	 */
	function getLastError() {
		return pg_last_error($this->conn->_connectionID);
	}
}

?>

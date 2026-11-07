<?php

/**
 * Help links for PostgreSQL 9.5 documentation
 *
 * $Id: PostgresDoc84.php,v 1.3 2008/11/18 21:35:48 ioguix Exp $
 */

include('./help/PostgresDoc13.php');

// The manual of the server's own version: 14, 15, ... ("devel" for
// development builds, "current" if the version can't be told).
$_ppa_doc_version = 'current';
if (isset($this->conn->_connectionID) && $this->conn->_connectionID) {
	$_ppa_v = @pg_parameter_status($this->conn->_connectionID, 'server_version');
	if (is_string($_ppa_v) && preg_match('/^(\d+)/', $_ppa_v, $_ppa_m) && (int) $_ppa_m[1] >= 10)
		$_ppa_doc_version = preg_match('/devel|alpha|beta|rc/i', $_ppa_v) ? 'devel' : $_ppa_m[1];
}
$this->help_base = sprintf($GLOBALS['conf']['help_base'], $_ppa_doc_version);

?>

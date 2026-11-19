<?php
	/**
	 * Does an export of a database, schema, or table (via pg_dump)
	 * to the screen or as a download.
	 *
	 * $Id: dbexport.php,v 1.22 2007/03/25 03:15:09 xzilla Exp $
	 */

	// Prevent timeouts on large exports
	set_time_limit(0);

	// Include application functions
	$_no_output = true;
	$f_schema = $f_object = '';
	include_once('./libraries/lib.inc.php');

	// Are we doing a cluster-wide dump or just a per-database dump
	$dumpall = ($_REQUEST['subject'] == 'server');
	
	// Check that database dumps are enabled.
	if ($misc->isDumpEnabled($dumpall)) {

		$server_info = $misc->getServerInfo();

		// Get the path of the pg_dump/pg_dumpall executable
		$exe = $misc->escapeShellCmd($server_info[$dumpall ? 'pg_dumpall_path' : 'pg_dump_path']);

		// Obtain the pg_dump version number and check if the path is good
		$version = array();
		preg_match("/(\d+(?:\.\d+)?)(?:\.\d+)?.*$/", exec($exe . " --version"), $version);

		if (empty($version)) {
			if ($dumpall)
				printf($lang['strbadpgdumpallpath'], $server_info['pg_dumpall_path']);
			else
				printf($lang['strbadpgdumppath'], $server_info['pg_dump_path']);
			exit;
		}

		// Make it do a download, if necessary
		switch($_REQUEST['output']){
			case 'show':
				header('Content-Type: text/plain');
				break;
			case 'download':
				// Set headers.  MSIE is totally broken for SSL downloading, so
				// we need to have it download in-place as plain text
				if (strstr(($_SERVER['HTTP_USER_AGENT'] ?? ''), 'MSIE') && isset($_SERVER['HTTPS'])) {
					header('Content-Type: text/plain');
				}
				else {
					header('Content-Type: application/download');
					header('Content-Disposition: attachment; filename=dump.sql');
				}
				break;
			case 'gzipped':
				// MSIE in SSL mode cannot do this - it should never get to this point
				header('Content-Type: application/download');
				header('Content-Disposition: attachment; filename=dump.sql.gz');
				break;
			default:
				// Whatever else was asked for, never let the browser guess.
				header('Content-Type: text/plain');
				break;
		}

		// Set environmental variables that pg_dump uses
		putenv('PGPASSWORD=' . $misc->loginPassword($server_info));
		putenv('PGUSER=' . $server_info['username']);
		$hostname = $server_info['host'];
		if ($hostname !== null && $hostname != '') {
			putenv('PGHOST=' . $hostname);
		}
		$port = $server_info['port'];
		if ($port !== null && $port != '') {
			putenv('PGPORT=' . $port);
		}
		// The same SSL settings the connection itself uses.
		$sslmode = Connection::sslmodeForLibpq($server_info['sslmode'] ?? null);
		if ($sslmode !== null) {
			putenv('PGSSLMODE=' . $sslmode);
		}
		if (!empty($server_info['sslrootcert'])) {
			putenv('PGSSLROOTCERT=' . $server_info['sslrootcert']);
		}

		// Build command for executing pg_dump.
		$cmd = $exe;
		
		// we are PG 7.4+, so we always have a schema
		if (isset($_REQUEST['schema'])) {
			$f_schema = $_REQUEST['schema'];
			$data->fieldClean($f_schema);
		}

		// Check for a specified table/view
		switch ($_REQUEST['subject']) {
		case 'schema':
			// This currently works for 8.2+ (due to the orthoganl -t -n issue introduced then)
			$cmd .= " -n " . $misc->escapeShellArg("\"{$f_schema}\"");
			break; 
		case 'table':
		case 'view':
			$f_object = $_REQUEST[$_REQUEST['subject']];
			$data->fieldClean($f_object);

			// Starting in 8.2, -n and -t are orthogonal, so we now schema qualify
			// the table name in the -t argument and quote both identifiers
			if ( ((float) $version[1]) >= 8.2 ) {
				$cmd .= " -t " . $misc->escapeShellArg("\"{$f_schema}\".\"{$f_object}\"");
            }
			else {
				// If we are 7.4 or higher, assume they are using 7.4 pg_dump and
				// set dump schema as well.  Also, mixed case dumping has been fixed
				// then..
				$cmd .= " -t " . $misc->escapeShellArg($f_object)
					. " -n " . $misc->escapeShellArg($f_schema);
			}
		}

		// Check for GZIP compression specified
		if ($_REQUEST['output'] == 'gzipped' && !$dumpall) {
			$cmd .= " -Z 9";
		}
				
		switch ($_REQUEST['what']) {
			case 'dataonly':
				$cmd .= ' -a';
				if ($_REQUEST['d_format'] == 'sql') $cmd .= ' --inserts';
				elseif (isset($_REQUEST['d_oids'])) $cmd .= ' -o';
				break;
			case 'structureonly':
				$cmd .= ' -s';
				if (isset($_REQUEST['s_clean'])) $cmd .= ' -c';
				break;
			case 'structureanddata':
				if ($_REQUEST['sd_format'] == 'sql') $cmd .= ' --inserts';
				elseif (isset($_REQUEST['sd_oids'])) $cmd .= ' -o';
				if (isset($_REQUEST['sd_clean'])) $cmd .= ' -c';
				break;
		}

		if (!$dumpall) {
			// The database this request is connected to: for a per-database
			// login that is always the one it is scoped to.
			putenv('PGDATABASE=' . $_curr_db);
		}

		// Lock wait and time limits (PPA_PG_DUMP_LOCK_WAIT_TIMEOUT,
		// PPA_PG_DUMP_MAX_MINUTES), see Misc::pgDumpCommand().
		$cmd = Misc::pgDumpCommand($cmd, $conf);

		// Who dumps what: a whole-database dump holds locks on every table
		// for as long as it runs.
		$what = $dumpall ? 'all databases' : ('database ' . $_curr_db
			. ($f_schema !== '' ? ", schema {$f_schema}" : '')
			. ($f_object !== '' ? ", {$_REQUEST['subject']} {$f_object}" : ''));
		$appUser = (isset($vault) && $vault->identity) ? $vault->identity->username : '?';
		$who = $appUser . ' as ' . ($server_info['username'] ?? '?')
			. ' on ' . ($server_info['desc'] ?? $server_info['host'] ?? '?');
		$started = microtime(true);
		error_log("phpPgAdmin pg_dump started by {$who}: {$what} ({$_REQUEST['what']})");

		// Execute command and return the output to the screen
		$status = null;
		passthru($cmd, $status);

		$seconds = round(microtime(true) - $started);
		if (Misc::pgDumpTimedOut($status, $conf)) {
			$minutes = Misc::pgDumpMaxMinutes($conf);
			error_log("phpPgAdmin pg_dump stopped after {$minutes} min (PPA_PG_DUMP_MAX_MINUTES) for {$who}: {$what}");
			// The SQL is cut off mid-way: say so where it ends. (A gzipped
			// dump is simply truncated and won't decompress.)
			if ($_REQUEST['output'] != 'gzipped')
				echo "\n-- phpPgAdmin: pg_dump was stopped after {$minutes} minutes (PPA_PG_DUMP_MAX_MINUTES).\n"
					. "-- THIS DUMP IS INCOMPLETE. Export less (one schema or table), or ask an administrator.\n";
		}
		else {
			error_log("phpPgAdmin pg_dump ended for {$who}: {$what}, exit status {$status} after {$seconds}s");
			// pg_dump's own message goes to the server log only; without this
			// a failed dump is just an empty or short file.
			if ($status !== 0 && $_REQUEST['output'] != 'gzipped')
				echo "\n-- phpPgAdmin: pg_dump failed (exit status {$status}), e.g. permission denied on a table,\n"
					. "-- or a table it could not lock in time. THIS DUMP IS INCOMPLETE. Ask an administrator for the server log.\n";
		}
	}

?>

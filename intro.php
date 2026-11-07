<?php

	/**
	 * Intro screen
	 *
	 * $Id: intro.php,v 1.19 2007/07/12 19:26:22 xzilla Exp $
	 */

	// Include application functions (no db conn)
	$_no_db_connection = true;
	include_once('./libraries/lib.inc.php');
	include_once('./themes/themes.php');

	$misc->printHeader();
	$misc->printBody();

	$misc->printTrail('root');
	$misc->printTabs('root','intro');
?>

<h2><?php echo htmlspecialchars($lang['strservers']) ?></h2>
<?php
	// Start here: the servers, each with whether you are logged in.
	$intro_servers = $misc->groupServersForTree($misc->getServers(false, false));
	if (count($intro_servers) > 0) {
		echo "<p>", htmlspecialchars($lang['strpickserver']), "</p>\n";
		echo "<ul class=\"intro-servers\">\n";
		foreach ($intro_servers as $srv) {
			$href = value($srv['action'], $srv, 'html');
			$icon = $misc->icon($srv['icon']);
			echo "\t<li><a href=\"{$href}\"><img src=\"", htmlspecialchars($icon), "\" alt=\"\" /> ",
				htmlspecialchars($srv['desc']), "</a> <span class=\"hint\">", htmlspecialchars($srv['tooltip'] ?? ''), "</span></li>\n";
		}
		echo "</ul>\n";
	}
?>

<h2><?php echo htmlspecialchars($lang['strsettings']) ?></h2>
<form method="get" action="intro.php">
<table>
	<tr class="data1">
		<th class="data"><?php echo $lang['strlanguage'] ?></th>
		<td>
			<select name="language" onchange="this.form.submit()">
			<?php
			$language = isset($_SESSION['webdbLanguage']) ? $_SESSION['webdbLanguage'] : 'english';
			foreach ($appLangFiles as $k => $v) {
				echo "\t<option value=\"{$k}\"",
					($k == $language) ? ' selected="selected"' : '',
					">{$v}</option>\n";
			}
			?>
			</select>
		</td>
	</tr>
	<tr class="data2">
		<th class="data"><?php echo $lang['strtheme'] ?></th>
		<td>
			<select name="theme" onchange="this.form.submit()">
			<?php
			foreach ($appThemes as $k => $v) {
				echo "\t<option value=\"{$k}\"",
					($k == $conf['theme']) ? ' selected="selected"' : '',
					">{$v}</option>\n";
			}
			?>
			</select>
		</td>
	</tr>
</table>
<noscript><p><input type="submit" value="<?php echo $lang['stralter'] ?>" /></p></noscript>
</form>

<p class="hint"><?php echo "$appName $appVersion" ?></p>

<ul class="intro">
	<li><a href="https://github.com/ReimuHakurei/phpPgAdmin"><?php echo $lang['strppahome'] ?></a></li>
	<li><a href="<?php echo $lang['strpgsqlhome_url'] ?>"><?php echo $lang['strpgsqlhome'] ?></a></li>
	<li><a href="https://github.com/ReimuHakurei/phpPgAdmin/issues"><?php echo $lang['strreportbug'] ?></a></li>
</ul>

<?php
	if (isset($_GET['language'])) $_reload_browser = true;
	$misc->printFooter();
?>

<?php
	include_once('./libraries/lib.inc.php');

	$_POST['offset'] = isset($_POST['offset']) ? (int)$_POST['offset'] : 0;
	$offset = " OFFSET {$_POST['offset']}";

	$keynames = array();
	foreach ($_POST['fkeynames'] as $k => $v) {
		$fkeynames[$k] = $v;
	}

	$keyspos = array_combine($fkeynames, $_POST['keys']);

	$f_schema = $_POST['f_schema'];
	$data->fieldClean($f_schema);
	$f_table = $_POST['f_table'];
	$data->fieldClean($f_table);
	$f_attname = $fkeynames[$_POST['fattpos'][0]];
	$data->fieldClean($f_attname);

	// Escape LIKE metacharacters in the user-supplied value so '%' and '_'
	// are matched literally ('@' is the escape character, not a backslash,
	// so this works whatever standard_conforming_strings is), then clean()
	// the result for the string literal.
	$fvalue = str_replace(array('@', '%', '_'), array('@@', '@%', '@_'), (string)$_POST['fvalue']);
	$data->clean($fvalue);

	$q = "SELECT *
		FROM \"{$f_schema}\".\"{$f_table}\"
		WHERE \"{$f_attname}\"::text LIKE '{$fvalue}%' ESCAPE '@'
		ORDER BY \"{$f_attname}\" LIMIT 12 {$offset};";

	$res = $data->selectSet($q);

	if (!$res->EOF) {
		echo "<table class=\"ac_values\">";
		echo '<tr>';
		foreach (array_keys($res->fields) as $h) {
			echo '<th>';

			if (in_array($h, $fkeynames))
				echo '<img src="'. $misc->icon('ForeignKey') .'" alt="[referenced key]" />';

			echo htmlentities($h, ENT_QUOTES, 'UTF-8'), '</th>';
			
		}
		echo "</tr>\n";
		$i=0;
		while ((!$res->EOF) && ($i < 11)) {
			$j=0;
			echo "<tr class=\"acline\">";
			foreach ($res->fields as $n => $v) {
				$finfo = $res->fetchField($j++);
				if (in_array($n, $fkeynames))
					echo "<td><a href=\"javascript:void(0)\" class=\"fkval\" name=\"", htmlspecialchars($keyspos[$n]), "\">",
						$misc->printVal($v, Misc::dataType($finfo->type), array('clip' => 'collapsed')),
						"</a></td>";
				else
					echo "<td><a href=\"javascript:void(0)\">",
						$misc->printVal($v, Misc::dataType($finfo->type), array('clip' => 'collapsed')),
						"</a></td>";
			}
			echo "</tr>\n";
			$i++;
			$res->moveNext();
		}		
		echo "</table>\n";

		$page_tests='';

		$js = "<script type=\"text/javascript\">\n";
		
		if ($_POST['offset']) {
			echo "<a href=\"javascript:void(0)\" id=\"fkprev\">&lt;&lt; Prev</a>";
			$js.= "fkl_hasprev=true;\n";
		}
		else
			$js.= "fkl_hasprev=false;\n";

		if ($res->recordCount() == 12) {
			$js.= "fkl_hasnext=true;\n";
			echo "&nbsp;&nbsp;&nbsp;<a href=\"javascript:void(0)\" id=\"fknext\">Next &gt;&gt;</a>";
		}
		else
			$js.= "fkl_hasnext=false;\n";
		
		echo $js ."</script>";
	}
	else {
		printf("<p>{$lang['strnofkref']}</p>", htmlspecialchars("\"{$_POST['f_schema']}\".\"{$_POST['f_table']}\".\"{$fkeynames[$_POST['fattpos'][0]]}\""));

		if ($_POST['offset'])
			echo "<a href=\"javascript:void(0)\" class=\"fkprev\">Prev &lt;&lt;</a>";
	}
?>

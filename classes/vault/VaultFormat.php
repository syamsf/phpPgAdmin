<?php

/**
 * Time wording for the vault pages. Uses the $lang strings and UTC, as the
 * stored timestamps are UTC.
 */
class VaultFormat {

	/** "3 minutes ago", "yesterday", "12 Jan 2026"; "never" for null. */
	public static function ago(?string $iso, int $nowTs): string {
		if ($iso === null || $iso === '') {
			return self::text('strvaultnever', 'never');
		}
		$ts = strtotime($iso);
		if ($ts === false) {
			return $iso;
		}
		$diff = $nowTs - $ts;
		if ($diff < 60) {
			return self::text('strvaultjustnow', 'just now');
		}
		if ($diff < 3600) {
			return sprintf(self::text('strvaultminutesago', '%d minutes ago'), intdiv($diff, 60));
		}
		$day = gmdate('Y-m-d', $ts);
		$nowDay = gmdate('Y-m-d', $nowTs);
		if ($day === $nowDay) {
			return self::text('strvaulttoday', 'today');
		}
		if ($day === gmdate('Y-m-d', $nowTs - 86400)) {
			return self::text('strvaultyesterday', 'yesterday');
		}
		$days = intdiv(strtotime($nowDay) - strtotime($day), 86400);
		if ($days < 14) {
			return sprintf(self::text('strvaultdaysago', '%d days ago'), $days);
		}
		if ($days < 60) {
			return sprintf(self::text('strvaultweeksago', '%d weeks ago'), intdiv($days, 7));
		}
		return gmdate('j M Y', $ts);
	}

	/** "12 Jan 2026" */
	public static function date(string $iso): string {
		$ts = strtotime($iso);
		return $ts === false ? $iso : gmdate('j M Y', $ts);
	}

	private static function text(string $key, string $fallback): string {
		global $lang;
		return isset($lang[$key]) ? $lang[$key] : $fallback;
	}
}

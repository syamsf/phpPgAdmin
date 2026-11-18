<?php

require_once(__DIR__ . '/VaultIdentity.php');

/**
 * SSO identity from the headers a trusted proxy sets, and the IP checks
 * behind it. The headers are only believed when the request comes from an
 * address in AUTH_TRUSTED_PROXIES: anyone else could send them too.
 */
class VaultAuth {

	const MAX_USERNAME_BYTES = 128;

	/**
	 * Is $ip inside one of $cidrs? IPv4 and IPv6; "::ffff:a.b.c.d" counts as
	 * IPv4. A bare address means just that address. Invalid entries never match.
	 */
	public static function ipInCidrs(string $ip, array $cidrs): bool {
		$addr = self::packIp($ip);
		if ($addr === null) {
			return false;
		}
		foreach ($cidrs as $cidr) {
			$net = self::parseCidr((string)$cidr);
			if ($net === null || strlen($net[0]) !== strlen($addr)) {
				continue;
			}
			if (self::prefixMatches($addr, $net[0], $net[1])) {
				return true;
			}
		}
		return false;
	}

	/**
	 * "10.0.0.0/8", "2001:db8::/32" or a bare address.
	 * @return array|null [packed network address, prefix length]
	 */
	public static function parseCidr(string $cidr) {
		$parts = explode('/', trim($cidr), 2);
		$raw = $parts[0] === '' ? false : @inet_pton($parts[0]);
		if ($raw === false) {
			return null;
		}
		$bits = strlen($raw) * 8;
		if (isset($parts[1])) {
			if (!ctype_digit($parts[1]) || strlen($parts[1]) > 3 || (int)$parts[1] > $bits) {
				return null;
			}
			$prefix = (int)$parts[1];
		} else {
			$prefix = $bits;
		}
		if (strlen($raw) === 16 && self::isMappedV4($raw) && $prefix >= 96) {
			return array(substr($raw, 12), $prefix - 96);
		}
		return array($raw, $prefix);
	}

	/**
	 * Comma-separated groups: trimmed, empty items dropped, duplicates
	 * removed, first-seen order kept.
	 */
	public static function parseGroups(string $value): array {
		$groups = array();
		foreach (explode(',', $value) as $group) {
			$group = trim($group);
			if ($group !== '' && !in_array($group, $groups, true)) {
				$groups[] = $group;
			}
		}
		return $groups;
	}

	/**
	 * The identity the proxy vouches for, or null with $why set to
	 * 'untrusted' (the request isn't from a trusted proxy) or 'missing'
	 * (no usable user header: empty, over 128 bytes, not UTF-8, or holding
	 * a control character or a comma).
	 */
	public static function ssoIdentity(array $server, array $cfg, ?string &$why) {
		$why = null;
		$remote = isset($server['REMOTE_ADDR']) ? (string)$server['REMOTE_ADDR'] : '';
		if (!self::ipInCidrs($remote, $cfg['trusted_proxies'])) {
			$why = 'untrusted';
			return null;
		}

		$user = self::header($server, $cfg['user_header']);
		$user = $user === null ? '' : trim($user);
		// Not empty, not oversized, valid UTF-8, no control characters, and
		// no comma (a username must never read as a list of groups).
		if ($user === '' || strlen($user) > self::MAX_USERNAME_BYTES || !preg_match('//u', $user)
			|| preg_match('/[\x00-\x1F\x7F,]/', $user)) {
			$why = 'missing';
			return null;
		}

		$groups = self::header($server, $cfg['groups_header']);
		return new VaultIdentity($user, self::parseGroups($groups === null ? '' : $groups),
			$cfg['admin_group'], 'sso');
	}

	private static function header(array $server, string $name) {
		$key = 'HTTP_' . strtoupper(str_replace('-', '_', $name));
		return isset($server[$key]) && is_string($server[$key]) ? $server[$key] : null;
	}

	/** Packed address, with IPv4-mapped IPv6 turned into IPv4. */
	private static function packIp(string $ip) {
		$raw = $ip === '' ? false : @inet_pton($ip);
		if ($raw === false) {
			return null;
		}
		return strlen($raw) === 16 && self::isMappedV4($raw) ? substr($raw, 12) : $raw;
	}

	private static function isMappedV4(string $raw): bool {
		return strncmp($raw, str_repeat("\0", 10) . "\xff\xff", 12) === 0;
	}

	private static function prefixMatches(string $addr, string $net, int $prefix): bool {
		$bytes = intdiv($prefix, 8);
		if ($bytes > 0 && strncmp($addr, $net, $bytes) !== 0) {
			return false;
		}
		$rest = $prefix % 8;
		if ($rest === 0) {
			return true;
		}
		$mask = (0xFF << (8 - $rest)) & 0xFF;
		return (ord($addr[$bytes]) & $mask) === (ord($net[$bytes]) & $mask);
	}
}

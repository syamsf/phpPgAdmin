<?php

/**
 * The person using the app, from the SSO headers or a local sign-in.
 * The rest of the app only looks at this, never at the sign-in mode.
 */
class VaultIdentity {

	/** @var string */
	public $username;
	/** @var string[] */
	public $groups;
	/** @var bool */
	public $isAdmin;
	/** @var string 'sso' or 'local' */
	public $mode;

	public function __construct(string $username, array $groups, string $adminGroup, string $mode) {
		$this->username = $username;
		$this->groups = array_values($groups);
		// Exact match only: "role-admins" or "Role-Admin" is not "role-admin".
		$this->isAdmin = $adminGroup !== '' && in_array($adminGroup, $this->groups, true);
		$this->mode = $mode;
	}
}

<?php

/**
 * Raised by the login vault code. The message is safe to show: it never holds
 * a stored password.
 */
class VaultError extends RuntimeException {}

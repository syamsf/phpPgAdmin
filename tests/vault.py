#!/usr/bin/env python3
"""
Login vault tests: app sign-in (SSO headers, local users), saved and shared
logins, against the three app containers of tests/compose.yaml.

    python3 tests/vault.py http://127.0.0.1:8080 http://127.0.0.1:8081 http://127.0.0.1:8082 [name-filter]

The first URL is the sso app (every address counts as the proxy), the second
the local-mode app, the third an sso app whose proxy list matches nobody.
"""

import html
import json
import os
import re
import subprocess
import sys
import traceback
import uuid

from security import Client, check, Failure

HERE = os.path.dirname(os.path.abspath(__file__))

OTHER = "db:5432:allow:ppa_other"
OTHER_TEST = "db:5432:allow:ppa_test"
TESTS = []
SSO = LOCAL = STRICT = None


def test(fn):
    TESTS.append(fn)
    return fn


def who(name, groups=""):
    """A client signed in by the proxy as name, in groups (comma-separated)."""
    return Client(SSO, OTHER, identity=(name, groups))


def topbar_user(page):
    m = re.search(r'<div class="topbar-user">(.*?)</div>', page, re.S)
    check(m, "no topbar-user block on the page")
    return m.group(1)


# --- Direct access to the vault, through the app container's php

VAULT_BOOT = (
    'chdir("/var/www/html"); $conf = array(); include "./conf/config.inc.php"; '
    'require_once "./classes/vault/Vault.php"; '
    '$config = VaultConfig::fromConf($conf); $db = VaultStore::open($config["db_path"]); '
    '$audit = new VaultAudit($db); '
    '$creds = new VaultCredentials($db, VaultCrypto::fromConfig($config), $audit); '
)


def vault_php(code, service="app"):
    """Runs PHP in the app container after a bootstrap that sets $conf,
    $config, $db (the vault's PDO), $audit and $creds. Returns stdout."""
    r = subprocess.run(
        ["docker", "compose", "-f", os.path.join(HERE, "compose.yaml"), "exec", "-T", service,
         "php", "-r", VAULT_BOOT + code],
        capture_output=True, timeout=120)
    out = r.stdout.decode("utf-8", "replace")
    check(r.returncode == 0, "vault_php exited %s: %s %s" % (r.returncode, out[-300:],
                                                            r.stderr.decode("utf-8", "replace")[-300:]))
    return out


def php_str(s):
    """A PHP single-quoted string literal."""
    return "'" + s.replace("\\", "\\\\").replace("'", "\\'") + "'"


# --- Identity from the sign-in proxy

@test
def test_topbar_shows_identity():
    status, page = who("alice", "dba").get("intro.php")
    check(status == 200, "intro.php answered HTTP %s" % status)
    user = topbar_user(page)
    check("<strong>alice</strong>" in user, "the top bar doesn't name alice: %r" % user)
    check("via SSO" in user, "the top bar doesn't say via SSO: %r" % user)
    check("vault-chip" not in page, "a non-admin gets the admin chip")
    check("signout.php" not in page, "Sign out shown in sso mode without AUTH_SIGNOUT_URL")


@test
def test_admin_chip():
    status, page = who("boss", "dba, role-admin").get("intro.php")
    check(status == 200, "intro.php answered HTTP %s" % status)
    check('<span class="vault-chip">role-admin</span>' in topbar_user(page), "no role-admin chip for an admin")
    status, page = who("boss", "role-admins").get("intro.php")
    check("vault-chip" not in page, "role-admins counted as role-admin")


@test
def test_missing_user_header_403():
    refused = "did not say who you are"
    status, page = Client(SSO, OTHER, identity=None).get("intro.php")
    check(status == 403 and refused in page, "no user header answered HTTP %s, expected 403" % status)
    check("topbar" not in page, "the app ran without a user header")
    status, page = who("   ", "role-admin").get("intro.php")
    check(status == 403 and refused in page, "a blank user header answered HTTP %s, expected 403" % status)
    status, page = Client(SSO, OTHER, identity=None).post("redirect.php", {"server": OTHER})
    check(status == 403 and refused in page, "a POST without a user header answered HTTP %s" % status)


@test
def test_untrusted_proxy_403():
    c = Client(STRICT, OTHER, identity=("alice", "role-admin"))
    for path in ("intro.php", "servers.php", "redirect.php"):
        status, page = c.get(path)
        check(status == 403, "%s from an untrusted address answered HTTP %s, expected 403" % (path, status))
        check("alice" not in page, "%s from an untrusted address shows the header's user" % path)


@test
def test_session_not_inherited_by_next_sso_user():
    # One browser (one cookie jar): alice logs in to a server by hand, signs
    # out at the proxy, and bob signs in there. Bob must not get her login.
    c = who("alice")
    status, page = c.login("vault_rot", "Rot-pass-1")
    check(status == 200 and "loginUsername" not in page, "login as vault_rot failed (HTTP %s)" % status)
    db_page = dict(server=OTHER, database="ppa_other", subject="database")
    status, page = c.get("database.php", **db_page)
    check(status == 200 and "loginUsername" not in page, "alice isn't logged in to ppa_other")

    c.opener.addheaders = [h for h in c.opener.addheaders if h[0] not in ("Remote-User", "Remote-Groups")]
    c.opener.addheaders += [("Remote-User", "bob"), ("Remote-Groups", "")]
    status, page = c.get("database.php", **db_page)
    check("<strong>bob</strong>" in page, "the page isn't for bob")
    check("loginUsername" in page, "bob inherited alice's database login")

    # And alice coming back doesn't get it back either: the session was cleared.
    c.opener.addheaders = [h for h in c.opener.addheaders if h[0] not in ("Remote-User", "Remote-Groups")]
    c.opener.addheaders += [("Remote-User", "alice"), ("Remote-Groups", "")]
    status, page = c.get("database.php", **db_page)
    check("loginUsername" in page, "the old session login survived the switch")


@test
def test_application_name():
    c = who("alice")
    status, page = c.login("vault_rot", "Rot-pass-1")
    check(status == 200 and "loginUsername" not in page, "login as vault_rot failed (HTTP %s)" % status)
    name = c.scalar("SELECT application_name FROM pg_stat_activity WHERE pid = pg_backend_pid()", "ppa_other")
    check(name == "phppgadmin:alice", "application_name is %r" % name)


# --- Saved logins on the database login page (board 1)

ROT_USER, ROT_PASSWORD = "vault_rot", "Rot-pass-1"
NOT_AVAILABLE = "This saved login is no longer available to you."
OPTGROUP = re.compile(r'<optgroup label="([^"]*)">(.*?)</optgroup>', re.S)
OPTION = re.compile(r'<option value="([^"]*)"([^>]*)>(.*?)</option>', re.S)


def login_page(c, server=OTHER, database="ppa_other"):
    """The login page of a database (or, logged in, the database itself)."""
    return c.get("redirect.php", subject="database", server=server, database=database)[1]


def saved_options(page):
    """The saved-login dropdown: [{group, id, label, attrs, text}]."""
    out = []
    for group, body in OPTGROUP.findall(page):
        for value, attrs, text in OPTION.findall(body):
            text = html.unescape(text)
            out.append({"group": html.unescape(group), "id": html.unescape(value), "attrs": attrs,
                        "text": text, "label": text.split(" — ")[0]})
    return out


def logout(c, server=OTHER):
    c.get("servers.php", action="logout", logoutServer=server)


def save_login(c, label, password=ROT_PASSWORD):
    """Logs c in by hand as vault_rot with "Save this login" ticked, then
    out again; returns the page after the login."""
    status, page = c.login(ROT_USER, password, extra={"loginSave": "on", "loginSaveLabel": label})
    logout(c)
    return page


def saved_id(user, label=None):
    """A new personal saved login of user for ppa_other, by its id."""
    label = label or "rot-" + uuid.uuid4().hex[:8]
    c = who(user)
    save_login(c, label)
    ids = [o["id"] for o in saved_options(login_page(c)) if o["label"] == label]
    check(len(ids) == 1, "%s's login %r wasn't saved" % (user, label))
    return ids[0]


def use_saved(c, cid, server=OTHER, database="ppa_other"):
    """Posts the saved-login form like a browser: page first, then the form."""
    login_page(c, server, database)
    return c.post("redirect.php", {"subject": "database", "server": server, "database": database,
                                   "loginServer": server, "loginCredential": cid})


def page_text(page):
    return html.unescape(re.sub(r"<[^>]+>", " ", page))


@test
def test_manual_save_after_success():
    c = who("alice")
    status, page = c.login(ROT_USER, ROT_PASSWORD, extra={"loginSave": "on", "loginSaveLabel": "rot"})
    check(status == 200 and "loginUsername" not in page, "login as vault_rot failed (HTTP %s)" % status)
    logout(c)
    page = login_page(c)
    mine = [o for o in saved_options(page) if o["group"] == "Mine" and o["label"] == "rot"]
    check(mine, "no option rot under Mine: %r" % saved_options(page))
    check("vault_rot" in mine[0]["text"] and "read-write" in mine[0]["text"], "option text is %r" % mine[0]["text"])
    check(ROT_PASSWORD not in page, "the login page holds the saved password")
    check('id="loginCredential"' in page and "data-vault-select" in page, "no saved-login select")
    check("Only the login's ID is sent. The password stays on the server." in page_text(page), "no lock note")
    check("or enter manually" in page, "no divider")
    check(re.search(r'<script src="js/vault\.js\?v=[^"]+"></script>', page), "js/vault.js isn't versioned")


@test
def test_save_failure_is_reported():
    # The login works but saving it fails (here: a trigger refuses the row).
    label = uniq("nosave")
    trigger = "t_" + label.replace("-", "_")
    vault_php('$db->exec("CREATE TRIGGER %s BEFORE INSERT ON credentials WHEN NEW.label = \'%s\' '
              'BEGIN SELECT RAISE(ABORT, \'no\'); END"); echo "ok";' % (trigger, label))
    try:
        c = who(uniq("nosaver"))
        status, page = c.login(ROT_USER, ROT_PASSWORD, extra={"loginSave": "on", "loginSaveLabel": label})
        check(status == 200 and "loginUsername" not in page, "the login failed (HTTP %s)" % status)
        check("The login worked but wasn't saved." in page_text(page), "no 'wasn't saved' message: %s" % flat(page)[:600])
        check("The login worked but wasn't saved." not in page_text(c.get("intro.php")[1]), "the message is shown twice")
        logout(c)
        check(label not in [o["label"] for o in saved_options(login_page(c))], "the login was saved anyway")
    finally:
        vault_php('$db->exec("DROP TRIGGER IF EXISTS %s"); echo "ok";' % trigger)


@test
def test_failed_manual_login_not_saved():
    c = who("carol")
    label = "carol-" + uuid.uuid4().hex[:8]
    status, page = c.login(ROT_USER, "Not-the-password", extra={"loginSave": "on", "loginSaveLabel": label})
    check("loginUsername" in page, "a wrong password logged in")
    page = login_page(c)
    check(not [o for o in saved_options(page) if o["label"] == label], "a failed login was saved")
    check(label not in page, "the label of a failed login shows up")


@test
def test_saved_login_works():
    cid = saved_id("alice")
    c = who("alice")
    status, page = use_saved(c, cid)
    check(status == 200 and "loginUsername" not in page, "the saved login didn't log in (HTTP %s)" % status)
    check("schemas.php" in page, "not the schemas page")
    check('<span class="username">vault_rot</span>' in page, "the top bar doesn't show vault_rot")
    check(ROT_PASSWORD not in page, "the page holds the password")
    # Nothing in the session file holds the password either.
    sid = session_cookie(c)
    check(sid and re.match(r"^[A-Za-z0-9,-]+$", sid), "no session cookie")
    out = vault_php('$p = (session_save_path() ?: sys_get_temp_dir()) . "/sess_" . %s; '
                    '$s = (string) @file_get_contents($p); '
                    'echo $s === "" ? "missing" : (strpos($s, %s) === false ? "clean" : "LEAK");'
                    % (php_str(sid), php_str(ROT_PASSWORD)))
    check(out == "clean", "session file check: %s" % out)


@test
def test_foreign_credential_id_refused():
    cid = saved_id("alice")
    cases = (
        ("bob posts alice's id", who("bob"), cid, OTHER, "ppa_other"),
        ("a random id", who("alice"), str(uuid.uuid4()), OTHER, "ppa_other"),
        ("alice's id for ppa_test", who("alice"), cid, OTHER_TEST, "ppa_test"),
    )
    for what, c, posted, server, database in cases:
        status, page = use_saved(c, posted, server, database)
        check("loginUsername" in page, "%s: logged in" % what)
        check(NOT_AVAILABLE in page_text(page), "%s: no 'no longer available' message" % what)
        check('<span class="username">vault_rot</span>' not in page, "%s: connected as vault_rot" % what)
        # Nothing was stored: the next page asks again, without the message.
        page = login_page(c, server, database)
        check("loginUsername" in page and NOT_AVAILABLE not in page_text(page), "%s: a login was stored" % what)


@test
def test_deleted_credential_in_session_is_dropped():
    cid = saved_id("alice2")
    c = who("alice2")
    status, page = use_saved(c, cid)
    check("loginUsername" not in page, "the saved login didn't log in")
    delete_via_page(c, cid)
    status, page = c.get("schemas.php", subject="database", server=OTHER, database="ppa_other")
    check("loginUsername" in page, "the next request still connected")
    check(NOT_AVAILABLE in page_text(page), "no 'no longer available' message")
    status, page = c.get("schemas.php", subject="database", server=OTHER, database="ppa_other")
    check("loginUsername" in page and NOT_AVAILABLE not in page_text(page), "the session login wasn't dropped")


@test
def test_password_change_marks_failed():
    user = uniq("alice")
    cid = saved_id(user)
    admin = Client(SSO, "db:5432:allow")
    status, page = admin.login("ppa", "ppa")
    check("loginUsername" not in page, "admin login failed")
    admin.sql("ALTER ROLE vault_rot PASSWORD 'Rot-pass-2'")
    try:
        c = who(user)
        status, page = use_saved(c, cid)
        text = page_text(page)
        check("loginUsername" in page, "logged in with the old password")
        check("no longer works" in text, "no 'no longer works' message: %s" % re.sub(r"\s+", " ", text)[-500:])
        check('href="vault.php?action=password&amp;id=%s"' % cid in page, "no Update password link")
        opt = [o for o in saved_options(page) if o["id"] == cid]
        check(opt and 'data-failed="1"' in opt[0]["attrs"], "the option isn't marked failed")
        check("password failed last time" in opt[0]["attrs"], "the option's meta doesn't say so")
        check("Rot-pass" not in page, "a password shows up")
    finally:
        admin.sql("ALTER ROLE vault_rot PASSWORD 'Rot-pass-1'")


@test
def test_rate_limit():
    c = who(uniq("dave"))
    for i in range(5):
        status, page = c.login(ROT_USER, "Wrong-pass-%d" % i)
        check("loginUsername" in page, "a wrong password logged in")
    status, page = c.login(ROT_USER, ROT_PASSWORD)
    check("loginUsername" in page, "logged in while locked")
    check("Too many failed logins. Try again in 5 minutes." in page_text(page), "no lockout message")


@test
def test_login_used_audited():
    cid = saved_id("alice")
    c = who("alice")
    status, page = use_saved(c, cid)
    check("loginUsername" not in page, "the saved login didn't log in")
    out = vault_php('$s = $db->prepare("SELECT server_id, \\"database\\", detail FROM audit_log '
                    'WHERE action = \'login_used\' AND actor = \'alice\' AND credential_id = ?"); '
                    '$s->execute(array(%s)); echo json_encode($s->fetchAll(PDO::FETCH_ASSOC));' % php_str(cid))
    rows = json.loads(out)
    check(len(rows) == 1, "%d login_used rows for the credential" % len(rows))
    check(rows[0]["server_id"] == "scoped" and rows[0]["database"] == "ppa_other", "row: %r" % rows[0])
    detail = json.loads(rows[0]["detail"])
    check(detail == {"pg_username": "vault_rot", "manual": False}, "detail: %r" % detail)


# --- My saved logins (board 3): vault.php

def my_page(c, **params):
    return c.get("vault.php", **params)[1]


def delete_via_page(c, cid):
    """Deletes a saved login the way the page does: confirm page, then POST."""
    page = my_page(c, action="delete", id=cid)
    check('name="action" value="dodelete"' in page, "no delete confirmation form: %s" % page_text(page)[-300:])
    status, page = c.post("vault.php", {"action": "dodelete", "id": cid})
    check(status == 200, "dodelete answered HTTP %s" % status)
    return page


def make_shared(label, pg_user, password, server_key, database, shares):
    """A shared login with its shares, inserted with the vault's own
    encryption (until the admin page exists). shares: [(type, principal,
    expires_at or None)], type is 'user' or 'group'. Returns its id."""
    rows = ", ".join("array(%s, %s, %s)" % (php_str(t), php_str(p), php_str(e) if e else "null")
                     for t, p, e in shares)
    out = vault_php(
        '$crypto = VaultCrypto::fromConfig($config); $id = VaultStore::uuid(); $now = VaultStore::now(); '
        'list($c, $n, $v) = $crypto->encrypt(%(pw)s, VaultCrypto::aad($id, %(key)s, %(user)s)); '
        '$st = $db->prepare("INSERT INTO credentials (id, kind, owner, label, server_id, \\"database\\", pg_username, '
        'password_enc, nonce, key_version, access_label, created_at, updated_at) '
        'VALUES (:id, \'shared\', \'boss\', :l, :s, :d, :u, :c, :n, :v, \'read-only\', :t, :t)"); '
        '$st->bindValue(":id", $id); $st->bindValue(":l", %(label)s); $st->bindValue(":s", %(key)s); '
        '$st->bindValue(":d", %(db)s); $st->bindValue(":u", %(user)s); '
        '$st->bindValue(":c", $c, PDO::PARAM_LOB); $st->bindValue(":n", $n, PDO::PARAM_LOB); '
        '$st->bindValue(":v", $v); $st->bindValue(":t", $now); $st->execute(); '
        'foreach (array(%(rows)s) as $sh) { $db->prepare("INSERT INTO credential_shares (credential_id, principal_type, '
        'principal, expires_at, granted_by, granted_at) VALUES (?, ?, ?, ?, \'boss\', ?)")'
        '->execute(array($id, $sh[0], $sh[1], $sh[2], $now)); } echo $id;'
        % {"pw": php_str(password), "key": php_str(server_key), "user": php_str(pg_user),
           "label": php_str(label), "db": php_str(database), "rows": rows})
    check(re.match(r"^[0-9a-f-]{36}$", out), "make_shared: %r" % out[-300:])
    return out


def uniq(prefix):
    return prefix + "-" + uuid.uuid4().hex[:8]


@test
def test_my_logins_lists_mine_only():
    label = uniq("mine")
    saved_id("lister", label)
    page = my_page(who("lister"))
    text = page_text(page)
    check(label in text, "my logins doesn't list %s" % label)
    check("Mine (" in text and "vault_rot" in text and "read-write" in text, "no Mine table: %s" % text[-400:])
    check("To add a login, open a database and tick \"Save this login\" when you log in." in text, "no add hint")
    check(re.search(r"Scoped\s+· \d+ logins?", text), "no server group row")
    for action in ("rename", "password", "delete"):
        check('action=%s&amp;id=' % action in page, "no %s link" % action)
    check('data-ppa-dialog="modal"' in page, "dialog links aren't marked")
    check(ROT_PASSWORD not in page, "the page holds the password")
    other = page_text(my_page(who("nolister")))
    check(label not in other, "another person's page lists %s" % label)
    check("Mine (0)" in other, "an empty page: %s" % other[-300:])


@test
def test_rename_and_access():
    c = who("renamer")
    cid = saved_id("renamer", uniq("old"))
    page = my_page(c, action="rename", id=cid)
    check('name="label"' in page and 'name="access"' in page, "no rename form")
    check('value="read-write" checked="checked"' in page, "access isn't preselected")
    label = uniq("rot ro")
    status, page = c.post("vault.php", {"action": "saverename", "id": cid, "label": label, "access": "read-only"})
    text = page_text(page)
    check(label in text and "read-only" in text, "not listed renamed: %s" % text[-400:])
    check('Saved login "%s" updated.' % label in text, "no message")
    status, page = c.post("vault.php", {"action": "saverename", "id": cid, "label": "x", "access": "root"})
    check("Access is read-only or read-write." in page_text(page), "a bad access was accepted")
    status, page = c.post("vault.php", {"action": "saverename", "id": cid, "label": "  ", "access": "read-only"})
    check("A label is 1 to 100 characters" in page_text(page), "a blank label was accepted")
    # The dropdown on the login page shows the new label.
    logout(c)
    check(label in [o["label"] for o in saved_options(login_page(c))], "the login page doesn't show the new label")


@test
def test_update_password_tests_first():
    c = who("pwupdater")
    cid = saved_id("pwupdater", uniq("pw"))
    vault_php('$creds->markFailed(%s); echo "ok";' % php_str(cid))
    page = my_page(c)
    check("Password failed" in page_text(page), "a failed login isn't flagged")
    form = my_page(c, action="password", id=cid)
    check('type="password"' in form and 'value=""' in form and ROT_PASSWORD not in form, "password form")
    check(re.search(r'<input type="submit" name="cancel"[^>]*formnovalidate', form), "Cancel is blocked by the empty password")
    status, page = c.post("vault.php", {"action": "savepassword", "id": cid, "password": "Wrong-pass-9"})
    text = page_text(page)
    check("was not changed." in text, "no 'not changed' message: %s" % text[-400:])
    check("password was wrong" in text or "password" in text.lower(), "no reason")
    check("Password failed" in text, "the status changed after a wrong password")
    check("Wrong-pass-9" not in page and "authentication failed" not in page, "raw text or password in the page")
    # The old password is still what is stored: the saved login still works.
    status, page = use_saved(who("pwupdater"), cid)
    check("loginUsername" not in page, "the old password was lost")
    status, page = c.post("vault.php", {"action": "savepassword", "id": cid, "password": ROT_PASSWORD})
    text = page_text(page)
    check("was updated." in text, "no success message: %s" % text[-400:])
    check("Password failed" not in text and " OK " in text, "the status isn't OK after the right password")


@test
def test_update_password_is_throttled_and_audited():
    user = uniq("pwguess")
    c = who(user)
    cid = saved_id(user, uniq("guess"))
    my_page(c)
    for i in range(5):
        status, page = c.post("vault.php", {"action": "savepassword", "id": cid, "password": "Wrong-guess-%d" % i})
        check("was not changed." in page_text(page), "try %d: %s" % (i, page_text(page)[-300:]))
    status, page = c.post("vault.php", {"action": "savepassword", "id": cid, "password": ROT_PASSWORD})
    text = page_text(page)
    check("Too many failed logins. Try again in 5 minutes." in text, "no lock after 5 wrong passwords: %s" % text[-400:])
    check("was updated." not in text, "a password was tried while locked")
    out = vault_php('$st = $db->prepare("SELECT credential_id, server_id, \\"database\\", detail FROM audit_log '
                    'WHERE action = \'login_failed\' AND actor = ? ORDER BY id"); $st->execute(array(%s)); '
                    'echo json_encode($st->fetchAll(PDO::FETCH_ASSOC));' % php_str(user))
    rows = json.loads(out)
    check(len(rows) == 5, "%d login_failed rows, expected 5" % len(rows))
    for row in rows:
        check(row["credential_id"] == cid and row["server_id"] == "scoped" and row["database"] == "ppa_other", "row: %r" % row)
        check(json.loads(row["detail"]) == {"pg_username": ROT_USER, "reason": "strloginbadpassword"}, "detail: %r" % row["detail"])
    check("Wrong-guess" not in out, "a tried password is in the audit log")
    # The same lock holds for logging in with it.
    status, page = use_saved(c, cid)
    check("loginUsername" in page and "Too many failed logins" in page_text(page), "logged in while locked")


@test
def test_delete_mine():
    c = who("deleter")
    label = uniq("gone")
    cid = saved_id("deleter", label)
    page = my_page(c, action="delete", id=cid)
    check('Delete saved login "%s"?' % label in page_text(page), "no confirmation text")
    page = delete_via_page(c, cid)
    text = page_text(page)
    check('Saved login "%s" deleted.' % label in text, "no message: %s" % text[-300:])
    check("Mine (0)" in text, "still listed")
    check(label not in [o["label"] for o in saved_options(login_page(c))], "still on the login page")


@test
def test_get_never_deletes():
    c = who("getter")
    label = uniq("keep")
    cid = saved_id("getter", label)
    my_page(c, action="dodelete", id=cid)
    my_page(c, action="saverename", id=cid, label="changed", access="read-only")
    check(label in page_text(my_page(c)), "a GET changed the login")


@test
def test_cannot_touch_other_users_login():
    label = uniq("alices")
    cid = saved_id("owner1", label)
    bob = who("intruder")
    my_page(bob)
    for what, fields in (
        ("saverename", {"label": "pwned", "access": "read-only"}),
        ("savepassword", {"password": "x"}),
        ("dodelete", {}),
    ):
        status, page = bob.post("vault.php", dict(fields, action=what, id=cid))
        check(NOT_AVAILABLE in page_text(page), "%s by another person: %s" % (what, page_text(page)[-300:]))
    for action in ("rename", "password", "delete"):
        page = my_page(bob, action=action, id=cid)
        check(NOT_AVAILABLE in page_text(page) and 'name="action"' not in page, "%s form shown to another person" % action)
    text = page_text(my_page(who("owner1")))
    check(label in text and "pwned" not in text, "alice's login changed: %s" % text[-300:])
    check("vault_rot" in text, "alice's login is gone")


@test
def test_shared_section_lists_group_share():
    label, direct = uniq("shared-group"), uniq("shared-direct")
    user, group = uniq("sharee"), uniq("dba")
    sid = make_shared(label, "vault_rot", ROT_PASSWORD, "scoped", "ppa_other", [("group", group, None)])
    make_shared(direct, "vault_rot", ROT_PASSWORD, "scoped", "ppa_other", [("user", user, "2099-11-30T00:00:00Z")])
    other = who(user, group)
    page = my_page(other)
    text = re.sub(r"\s+", " ", page_text(page))
    check("Shared with me (2)" in text, "shared count: %s" % text[-500:])
    check(label in text and "group " + group in text and "no expiry" in text, "group share isn't listed: %s" % text[-500:])
    check(direct in text and "you directly" in text and "30 Nov 2099" in text, "direct share isn't listed")
    check("You have it through" in text and "Admins manage shared logins." in text, "headers or lock note missing")
    check(ROT_PASSWORD not in page, "the page holds a shared password")
    check("action=rename" not in page.split("vault-shared-h")[1], "shared rows have actions")
    nobody = page_text(my_page(who("stranger", "finance")))
    check(label not in nobody and direct not in nobody, "a stranger sees shared logins")
    # Not mine: this page's actions refuse a shared id, even for an admin.
    boss = who("sboss", "role-admin")
    my_page(boss)
    status, page = boss.post("vault.php", {"action": "dodelete", "id": sid})
    check(NOT_AVAILABLE in page_text(page), "an admin deleted a shared login here")
    check(label in page_text(my_page(other)), "the shared login is gone")


# --- Local mode: app accounts (run.sh adds admin and lock-me with bin/vault)

ADMIN_PASSWORD = "Admin-pass-123456"


def local():
    """A browser on the local-mode app, not signed in."""
    return Client(LOCAL, OTHER, identity=None)


def signin(c, user, password, next=None):
    """Like a browser: open the sign-in page (for its token), then post it."""
    c.get("signin.php", **({"next": next} if next else {}))
    data = {"username": user, "password": password}
    if next:
        data["next"] = next
    return c.post("signin.php", data)


def alert(page):
    m = re.search(r'role="alert"[^>]*>(.*?)</div>', page, re.S)
    return re.sub(r"<[^>]+>", "", m.group(1)).strip() if m else None


def session_cookie(c):
    for h in c.opener.handlers:
        jar = getattr(h, "cookiejar", None)
        if jar is not None:
            for cookie in jar:
                if cookie.name == "PPA_ID":
                    return cookie.value
    return None


@test
def test_local_redirects_to_signin():
    c = local()
    status, page = c.get("intro.php")
    check(status == 200, "intro.php answered HTTP %s" % status)
    check(c.final_url.endswith("/signin.php?next=intro.php"), "intro.php ended on %s" % c.final_url)
    check('name="username"' in page and 'name="password"' in page, "no sign-in form")
    check("Use your phpPgAdmin account, not a database login." in page, "the card's intro is missing")
    check("Forgot your password? Ask an admin to reset it." in page, "the forgot-password hint is missing")
    check("topbar" not in page and "ppa-sidebar" not in page, "the app shell was shown before signing in")


@test
def test_local_partial_gets_401():
    c = local()
    status, page = c._open(c.url("intro.php"), None, {"X-PPA-Partial": "1"})
    check(status == 401, "a partial request answered HTTP %s, expected 401" % status)
    check(c.headers.get("X-PPA-Signin") == "signin.php", "X-PPA-Signin is %r" % c.headers.get("X-PPA-Signin"))


@test
def test_local_wrong_password_message():
    for user in ("admin", "nobody"):
        c = local()
        status, page = signin(c, user, "Wrong-pass-123456")
        check(c.final_url.endswith("/signin.php"), "a wrong password for %s ended on %s" % (user, c.final_url))
        check(alert(page) == "Wrong username or password.", "the alert for %s is %r" % (user, alert(page)))
        check("Wrong-pass-123456" not in page, "the typed password came back in the page")
        status, page = c.get("signin.php")
        check(alert(page) is None, "the message is shown twice")


@test
def test_local_signin_and_signout():
    c = local()
    c.get("intro.php")
    before = session_cookie(c)
    status, page = c.post("signin.php", {"username": "admin", "password": ADMIN_PASSWORD, "next": "intro.php"})
    check(status == 200 and c.final_url.endswith("/intro.php"), "sign-in ended on %s (HTTP %s)" % (c.final_url, status))
    check(session_cookie(c) not in (None, before), "the session id didn't change at sign-in")
    user = topbar_user(page)
    check("<strong>admin</strong>" in user, "the top bar doesn't name admin: %r" % user)
    check("local account" in user, "the top bar doesn't say local account: %r" % user)
    check('<span class="vault-chip">role-admin</span>' in user, "no admin chip for admin")

    status, page = c.post("signout.php", {})
    check(c.final_url.endswith("/signin.php"), "sign out ended on %s" % c.final_url)
    status, page = c.get("intro.php")
    check(c.final_url.endswith("/signin.php?next=intro.php"), "still signed in after sign out: %s" % c.final_url)

    # The app shell's sign out: a 401 that says where to go.
    signin(c, "admin", ADMIN_PASSWORD)
    c.get("intro.php")
    status, page = c._open(c.base + "signout.php", ("ppa_csrf=" + c.token).encode(), {"X-PPA-Partial": "1"})
    check(status == 401 and c.headers.get("X-PPA-Signin") == "signin.php",
          "a partial sign out answered HTTP %s, X-PPA-Signin %r" % (status, c.headers.get("X-PPA-Signin")))
    c.get("intro.php")
    check(c.final_url.endswith("/signin.php?next=intro.php"), "still signed in after a partial sign out")


@test
def test_local_next_stays_on_site():
    for next in ("https://example.com/", "//example.com/x.php", "intro.php\r\nX-Bad: 1", "../intro.php"):
        c = local()
        status, page = signin(c, "admin", ADMIN_PASSWORD, next=next)
        check(c.final_url.startswith(LOCAL.rstrip("/") + "/intro.php"), "next=%r ended on %s" % (next, c.final_url))
    c = local()
    signin(c, "admin", ADMIN_PASSWORD, next="servers.php?action=tree")
    check(c.final_url.endswith("/servers.php?action=tree"), "next to an app page ended on %s" % c.final_url)


@test
def test_failed_signin_never_audits_typed_name():
    typed = "Typed-Secret-" + uuid.uuid4().hex[:8]
    signin(local(), typed, "Wrong-pass-123456")
    out = vault_php('$st = $db->prepare("SELECT COUNT(*) FROM audit_log WHERE actor LIKE ? OR detail LIKE ?"); '
                    '$st->execute(array("%Typed-Secret%", "%Typed-Secret%")); $n = $st->fetchColumn(); '
                    '$last = $db->query("SELECT actor FROM audit_log WHERE action = \'signin_failed\' ORDER BY id DESC LIMIT 1")->fetchColumn(); '
                    'echo $n, " ", $last;', service="app_local")
    check(out == "0 (unknown)", "audit for an unknown name: %r" % out)
    # A real account is still named.
    signin(local(), "admin", "Wrong-pass-123456")
    out = vault_php('echo $db->query("SELECT actor FROM audit_log WHERE action = \'signin_failed\' ORDER BY id DESC LIMIT 1")->fetchColumn();',
                    service="app_local")
    check(out == "admin", "audit for a known name: %r" % out)
    admin_client()  # a good sign-in clears admin's failed count


@test
def test_local_lockout():
    c = local()
    for i in range(5):
        signin(c, "lock-me", "Wrong-pass-12345%d" % i)
    status, page = signin(c, "lock-me", "Lock-pass-123456")
    check(c.final_url.endswith("/signin.php"), "lock-me signed in while locked: %s" % c.final_url)
    check(alert(page) == "Too many failed sign-ins. Try again in 5 minutes.", "the alert is %r" % alert(page))


@test
def test_cli_rejects_duplicate():
    r = subprocess.run(
        ["docker", "compose", "-f", os.path.join(HERE, "compose.yaml"), "exec", "-T", "app_local",
         "php", "bin/vault", "user:add", "admin"],
        input=b"Another-pass-123456\n", capture_output=True, timeout=120)
    out = (r.stdout + r.stderr).decode("utf-8", "replace")
    check(r.returncode == 1, "user:add of an existing name exited %s: %s" % (r.returncode, out))
    check("already a user" in out, "unexpected message: %r" % out)
    check("Another-pass" not in out, "the CLI printed the password")
    check(len(out.strip().splitlines()) == 1, "more than one line: %r" % out)


def add_user(admin, name, password, groups="dba"):
    admin.get("vault_users.php", action="add")
    return admin.post("vault_users.php", {"action": "saveadd", "username": name, "display_name": name.title(),
                                          "password": password, "groups": groups})


def admin_client():
    c = local()
    signin(c, "admin", ADMIN_PASSWORD)
    return c


@test
def test_admin_adds_user_who_signs_in():
    admin = admin_client()
    name = uniq("erin")
    status, page = add_user(admin, name, "Erin-pass-123456")
    check('User "%s" added.' % name in page_text(page), "no added message: %r" % page_text(page)[:300])
    check(">%s<" % name in page and ">dba<" in page, "erin and her group are not listed")
    erin = local()
    signin(erin, name, "Erin-pass-123456", next="intro.php")
    check(erin.final_url.endswith("/intro.php"), "erin ended on %s" % erin.final_url)
    status, page = add_user(admin, name, "Erin-pass-123456")
    check("There is already a user with that name." in page, "a duplicate was not refused")
    status, page = add_user(admin, "short-pw", "short")
    check("at least 12 characters" in page, "a short password was accepted")


@test
def test_reset_password():
    admin = admin_client()
    name = uniq("erin-reset")
    add_user(admin, name, "Erin-pass-123456")
    admin.get("vault_users.php", action="password", user=name)
    status, page = admin.post("vault_users.php", {"action": "savepassword", "user": name, "password": "Erin-new-pass-123456"})
    check("was reset" in page, "no reset message")
    check("Erin-new-pass" not in page, "the password came back in the page")
    c = local()
    signin(c, name, "Erin-pass-123456")
    check(c.final_url.endswith("/signin.php"), "the old password still works")
    c = local()
    signin(c, name, "Erin-new-pass-123456", next="intro.php")
    check(c.final_url.endswith("/intro.php"), "the new password fails: %s" % c.final_url)


@test
def test_set_groups():
    admin = admin_client()
    name = uniq("erin-groups")
    add_user(admin, name, "Erin-pass-123456", groups="")
    status, page = admin.post("vault_users.php", {"action": "savegroups", "user": name, "groups": " ops , dev,,ops"})
    check("updated" in page and ">ops<" in page and ">dev<" in page, "groups not shown")
    status, page = admin.post("vault_users.php", {"action": "savegroups", "user": name, "groups": "x" * 65})
    check("1 to 64 characters" in page, "a long group name was accepted")


@test
def test_disable_ends_session():
    admin = admin_client()
    name = uniq("erin-off")
    add_user(admin, name, "Erin-pass-123456")
    erin = local()
    signin(erin, name, "Erin-pass-123456", next="intro.php")
    check(erin.final_url.endswith("/intro.php"), "erin did not sign in")
    # A GET only shows the confirmation
    status, page = admin.get("vault_users.php", action="dodisable", user=name)
    status, page = erin.get("intro.php")
    check(erin.final_url.endswith("/intro.php"), "a GET disabled erin")
    status, page = admin.get("vault_users.php", action="disable", user=name)
    check("Disable user" in page, "no confirmation")
    status, page = admin.post("vault_users.php", {"action": "dodisable", "user": name})
    check("disabled" in page.lower() and "Enable" in page, "erin is not shown as disabled")
    erin.get("intro.php")
    check(erin.final_url.endswith("/signin.php?next=intro.php") or "/signin.php" in erin.final_url,
          "erin's next GET ended on %s" % erin.final_url)
    c = local()
    signin(c, name, "Erin-pass-123456")
    check(c.final_url.endswith("/signin.php"), "a disabled user signed in")
    admin.post("vault_users.php", {"action": "doenable", "user": name})
    c = local()
    signin(c, name, "Erin-pass-123456", next="intro.php")
    check(c.final_url.endswith("/intro.php"), "an enabled user can't sign in")


@test
def test_cannot_disable_self():
    admin = admin_client()
    status, page = admin.post("vault_users.php", {"action": "dodisable", "user": "admin"})
    check("You can't do that to your own account." in page.replace("&#039;", "'"), "no refusal: %r" % page_text(page)[:300])
    status, page = admin.post("vault_users.php", {"action": "savegroups", "user": "admin", "groups": "dba"})
    check("your own account" in page, "admin group removed from self")
    status, page = admin.get("intro.php")
    check(admin.final_url.endswith("/intro.php"), "admin was signed out")


@test
def test_non_admin_gets_403():
    admin = admin_client()
    name = uniq("erin-plain")
    add_user(admin, name, "Erin-pass-123456")
    erin = local()
    signin(erin, name, "Erin-pass-123456", next="intro.php")
    status, page = erin.get("vault_users.php")
    check(status == 403, "a non-admin got HTTP %s" % status)
    status, page = erin.get("intro.php")
    check('vault_users.php' not in page, "the Users tab is shown to a non-admin")


@test
def test_sso_users_page():
    name = uniq("sso-seen")
    seen = who(name, "dba")
    status, _ = seen.get("intro.php")
    check(status == 200, "a new sso user got HTTP %s" % status)
    c = Client(SSO, OTHER, identity=("ppa-test", "role-admin"))
    status, page = c.get("intro.php")
    check('href="vault_users.php"' in page, "no Users tab for an sso admin")
    status, page = c.get("vault_users.php")
    text = flat(page)
    check(status == 200, "sso mode answered HTTP %s" % status)
    check("Everyone your sign-in provider has let in" in text, "no sso intro: %s" % text[:600])
    check(re.search(r"%s Active \d+ \w+ \d{4} just now" % re.escape(name), text), "%s isn't listed: %s" % (name, text[-1500:]))
    check("First seen" in text and "Display name" not in text, "wrong columns")
    check("Add user" not in text and "Reset password" not in text and "action=groups" not in page, "local-only actions shown")
    # Local-only actions are refused
    status, page = c.get("vault_users.php", action="add")
    check(status == 404 and "Passwords and groups are managed by your sign-in provider." in flat(page), "add in sso: HTTP %s" % status)
    status, page = c.post("vault_users.php", {"action": "savepassword", "user": name, "password": "Whatever-pass-1234"})
    check(status == 404, "savepassword in sso: HTTP %s" % status)
    # Disable blocks them at the proxy door; enable lets them back in
    status, page = c.get("vault_users.php", action="disable", user=name)
    check("Disable user" in flat(page), "no confirmation")
    status, page = c.post("vault_users.php", {"action": "dodisable", "user": name})
    check(re.search(r"%s Disabled" % re.escape(name), flat(page)), "%s isn't shown as disabled" % name)
    status, page = seen.get("intro.php")
    check(status == 403 and "Your account is disabled." in page, "a disabled sso user got HTTP %s" % status)
    c.post("vault_users.php", {"action": "doenable", "user": name})
    status, _ = seen.get("intro.php")
    check(status == 200, "an enabled sso user got HTTP %s" % status)
    status, page = c.post("vault_users.php", {"action": "dodisable", "user": "ppa-test"})
    check("your own account" in page, "an sso admin disabled themself")
    c = Client(SSO, OTHER, identity=("plain", "dba"))
    status, page = c.get("vault_users.php")
    check(status == 403, "a non-admin in sso got HTTP %s" % status)


# --- Shared logins (board 4): vault_admin.php

def boss():
    """An sso admin."""
    return who("boss", "role-admin")


def admin_get(c, **params):
    return c.get("vault_admin.php", **params)[1]


def share_via_page(admin, cid, ptype, principal, expires=""):
    """Shares like the panel's form: the panel first (for the token), then the POST."""
    admin_get(admin, id=cid)
    return admin.post("vault_admin.php", {"action": "share", "id": cid, "type": ptype,
                                          "principal": principal, "expires": expires})[1]


def unshare_via_page(admin, cid, ptype, principal):
    admin_get(admin, id=cid)
    return admin.post("vault_admin.php", {"action": "unshare", "id": cid, "type": ptype, "principal": principal})[1]


def rot_shared(label, shares=()):
    """A shared login for vault_rot on Scoped / ppa_other."""
    boss().get("intro.php")  # the first request of a fresh stack adds the env servers to the vault
    return make_shared(label, ROT_USER, ROT_PASSWORD, "scoped", "ppa_other", list(shares))


def flat(page):
    return re.sub(r"\s+", " ", page_text(page))


@test
def test_non_admin_403():
    c = who(uniq("alice"), "dba")
    for params in ({}, {"action": "audit"}):
        status, page = c.get("vault_admin.php", **params)
        check(status == 403, "a non-admin got HTTP %s for %r" % (status, params))
    status, page = c.get("intro.php")
    check("vault_admin.php" not in page, "the Shared logins tab is shown to a non-admin")
    status, page = boss().get("intro.php")
    check('href="vault_admin.php"' in page, "no Shared logins tab for an admin")


@test
def test_share_to_group_shows_in_dropdown():
    label = uniq("grp-share")
    cid = rot_shared(label)
    admin = boss()
    text = flat(admin_get(admin))
    check("Shared logins" in text and "Admins only. People you share with can use a login but never see its password."
          " Neither can admins." in text, "no header: %s" % text[:600])
    check("+ New shared login" in text, "no New shared login link")
    check(re.search(r"Scoped · env · \d+ shared logins?", text), "no server group row: %s" % text[:800])
    check(label in text and "not shared yet" in text, "the new login isn't listed as not shared")
    check('Status turns to "Password failed" when anyone\'s login with it fails.' in text, "no status note")

    page = share_via_page(admin, cid, "group", "dba")
    text = flat(page)
    check("Sharing: %s" % label in text, "no side panel: %s" % text[-800:])
    check("Scoped / ppa_other · vault_rot" in text, "no panel subline")
    check("Has access (1)" in text and "group dba" in text, "dba isn't listed: %s" % text[-800:])
    check("added by boss" in text and "no expiry" in text, "no share meta")
    check(re.search(r"%s ppa_other vault_rot read-only 1 group OK" % re.escape(label), text), "summary row: %s" % text[:1200])
    check('<datalist id="vault-principals-user">' in page and '<datalist id="vault-principals-group">' in page,
          "no name suggestions")
    m = re.search(r'<datalist id="vault-principals-group">(.*?)</datalist>', page, re.S)
    check(m and '<option value="dba"' in m.group(1), "dba isn't suggested as a group")
    m = re.search(r'<datalist id="vault-principals-user">(.*?)</datalist>', page, re.S)
    check(m and '<option value="dba"' not in m.group(1), "a group is suggested as a user")

    alice = who(uniq("alice"), "dba")
    opts = [o for o in saved_options(login_page(alice)) if o["label"] == label]
    check(opts and opts[0]["group"] == "Shared with me", "alice (dba) doesn't get %s: %r" % (label, opts))
    bob = who(uniq("bob"), "finance")
    check(label not in [o["label"] for o in saved_options(login_page(bob))], "bob (finance) gets the dba share")


@test
def test_shared_password_never_in_admin_pages():
    user = uniq("pwcheck")
    cid = rot_shared(uniq("pw-hidden"), [("user", user, None)])
    status, page = use_saved(who(user), cid)
    check("loginUsername" not in page, "the shared login didn't log in")
    admin = boss()
    for params in ({}, {"id": cid}, {"action": "edit", "id": cid}, {"action": "edit"}, {"action": "audit"},
                   {"action": "audit", "credential_id": cid}, {"action": "delete", "id": cid}):
        status, page = admin.get("vault_admin.php", **params)
        check(status == 200, "%r answered HTTP %s" % (params, status))
        check(ROT_PASSWORD not in page and "Rot-pass" not in page, "%r holds the shared password" % params)
        check("Fatal error" not in page and "Warning" not in page, "%r has a PHP error" % params)


@test
def test_revoked_share_stops_next_request():
    user = uniq("revoked")
    cid = rot_shared(uniq("revoke-me"), [("user", user, None)])
    c = who(user)
    status, page = use_saved(c, cid)
    check("loginUsername" not in page, "the shared login didn't log in")
    db_page = dict(subject="database", server=OTHER, database="ppa_other")
    status, page = c.get("schemas.php", **db_page)
    check("loginUsername" not in page, "not logged in before the revoke")
    # A GET never removes a share.
    admin = boss()
    admin_get(admin, action="unshare", id=cid, type="user", principal=user)
    status, page = c.get("schemas.php", **db_page)
    check("loginUsername" not in page, "a GET removed the share")
    page = unshare_via_page(admin, cid, "user", user)
    check("Has access (0)" in flat(page), "the share is still listed: %s" % flat(page)[-600:])
    status, page = c.get("schemas.php", **db_page)
    check("loginUsername" in page, "the next request still connected")
    check(NOT_AVAILABLE in page_text(page), "no 'no longer available' message")


@test
def test_expiry_in_past_rejected():
    import datetime
    user = uniq("expiry")
    label = uniq("expiring")
    cid = rot_shared(label)
    admin = boss()
    today = datetime.datetime.now(datetime.timezone.utc).date()
    page = share_via_page(admin, cid, "user", user, (today - datetime.timedelta(days=1)).isoformat())
    text = flat(page)
    check("The expiry date can't be in the past." in text, "no error for yesterday: %s" % text[-600:])
    check("Has access (0)" in text, "yesterday's share was added")
    page = share_via_page(admin, cid, "user", user, "2026-02-30")
    check("An expiry date looks like 2026-12-31." in flat(page), "a bad date was accepted")
    check(label not in [o["label"] for o in saved_options(login_page(who(user)))], "the rejected share gives access")
    page = share_via_page(admin, cid, "user", user, today.isoformat())
    text = flat(page)
    check("Has access (1)" in text and "expires " + "%d %s" % (today.day, today.strftime("%b %Y")) in text,
          "today's share isn't listed with its expiry: %s" % text[-600:])
    check(label in [o["label"] for o in saved_options(login_page(who(user)))], "today's share gives no access")


@test
def test_panel_recent_activity():
    user = uniq("active")
    cid = rot_shared(uniq("activity"))
    admin = boss()
    share_via_page(admin, cid, "user", user)
    status, page = use_saved(who(user), cid)
    check("loginUsername" not in page, "the shared login didn't log in")
    page = admin_get(admin, id=cid)
    text = flat(page)
    check("Recent activity" in text, "no Recent activity")
    check("%s used it" % user in text, "no '%s used it': %s" % (user, text[-800:]))
    check("boss shared it with %s" % user in text, "no share row in the activity")
    check('href="vault_admin.php?action=audit&amp;credential_id=%s"' % cid in page, "no Full audit log link")
    for link in ('vault_admin.php?action=edit&amp;id=%s"' % cid, 'vault_admin.php?action=edit&amp;id=%s#vault-password"' % cid):
        check(link in page, "no link %s" % link)
    check(re.search(r'<a href="vault_admin.php\?action=delete&amp;id=%s" data-ppa-dialog="modal"' % cid, page),
          "no Delete shared login dialog link")


@test
def test_audit_hides_personal_labels():
    user = uniq("auditee")
    label = uniq("rot")
    cid = saved_id(user, label)
    status, page = use_saved(who(user), cid)
    check("loginUsername" not in page, "the personal login didn't log in")
    admin = boss()
    for params in ({"action": "audit", "actor": user}, {"action": "audit", "credential_id": cid}, {"action": "audit"},
                   {"id": cid}):
        status, page = admin.get("vault_admin.php", **params)
        check(label not in page, "%r shows the personal label" % params)
    text = flat(admin_get(admin, action="audit", actor=user))
    check("personal login" in text, "no 'personal login': %s" % text[-800:])
    check("login_used" in text and "login_saved" in text, "the rows aren't listed")
    check("When Who Action Login Server / database IP Detail" in text, "no audit table header")
    check("pg_username: vault_rot" in text, "the detail isn't shown as key: value")
    # And an admin can't use or manage it from this page.
    admin.post("vault_admin.php", {"action": "dodelete", "id": cid})
    check(label in page_text(my_page(who(user))), "an admin deleted a personal login")


@test
def test_delete_shared_login():
    user = uniq("deleted")
    label = uniq("to-delete")
    cid = rot_shared(label, [("user", user, None)])
    admin = boss()
    page = admin_get(admin, action="delete", id=cid)
    check('Delete shared login "%s"?' % label in page_text(page), "no confirmation: %s" % flat(page)[-400:])
    admin_get(admin, action="dodelete", id=cid)
    check(label in page_text(admin_get(admin)), "a GET deleted the login")
    status, page = admin.post("vault_admin.php", {"action": "dodelete", "id": cid})
    text = flat(page)
    check('Shared login "%s" deleted.' % label in text, "no message: %s" % text[-400:])
    check(label not in text.replace('Shared login "%s" deleted.' % label, ""), "still listed")
    check(label not in [o["label"] for o in saved_options(login_page(who(user)))], "the user still has it")
    text = flat(admin_get(admin, action="audit", credential_id=cid))
    check("deleted login" in text and "credential_deleted" in text, "the audit doesn't show the deleted login")


@test
def test_shared_login_cannot_change_own_password():
    # The account pages are server pages, so this needs a whole-server
    # login (Test, through "postgres"): the fixture role app can do that.
    user = uniq("pwchanger")
    server = "db:5432:allow"
    boss().get("intro.php")
    cid = make_shared(uniq("no-alter"), "app", "app", "test", "postgres", [("user", user, None)])
    c = who(user)
    status, page = use_saved(c, cid, server, "postgres")
    check("loginUsername" not in page, "the shared login didn't log in")
    refused = "You are logged in with a shared login. Its password can't be changed here."
    new = "App-pass-changed-9"
    try:
        for script in ("roles.php", "users.php"):
            status, page = c.get(script, action="account", server=server)
            check("Change password" in page_text(page), "%s isn't the account page" % script)
            status, page = c.get(script, action="confchangepassword", server=server)
            check(refused in page_text(page), "%s shows the change-password form: %s" % (script, flat(page)[-400:]))
            check('name="confirm"' not in page, "%s has a password form" % script)
            status, page = c.post(script, {"action": "changepassword", "server": server, "password": new,
                                           "confirm": new, "ok": "OK"})
            check(refused in page_text(page), "%s took the POST: %s" % (script, flat(page)[-400:]))
        status, page = Client(SSO, server, identity=(uniq("checker"), "")).login("app", "app")
        check("loginUsername" not in page, "the role's password changed")
    finally:
        fixer = Client(SSO, server)
        fixer.login("ppa", "ppa")
        fixer.sql("ALTER ROLE app PASSWORD 'app'")


# --- New / edit shared login (board 5)

def form_page(admin, cid=None):
    params = {"action": "edit"}
    if cid:
        params["id"] = cid
    return admin_get(admin, **params)


def post_form(admin, action, cid=None, **over):
    """Posts the shared login form like a browser: the form page first, then the POST."""
    form_page(admin, cid)
    data = {"action": action, "server_id": "scoped", "database": "ppa_other", "label": "x",
            "pg_username": ROT_USER, "password": ROT_PASSWORD, "access_label": "read-only"}
    data.update(over)
    if cid:
        data["id"] = cid
    return admin.post("vault_admin.php", data)[1]


def created_id(page, label):
    """The id of the login the panel shows after a save."""
    m = re.search(r'action=edit&amp;id=([0-9a-f-]{36})', page)
    check(m, "no panel after the save: %s" % flat(page)[-400:])
    return m.group(1)


def login_ok(user, cid):
    status, page = use_saved(who(user), cid)
    return status == 200 and "schemas.php" in page


@test
def test_create_shared_tests_first():
    label = uniq("new-shared")
    admin = boss()
    admin.get("intro.php")
    page = post_form(admin, "save", label=label, password="not-the-password")
    check("Login failed" in page or "password" in flat(page).lower(), "no failure message: %s" % flat(page)[-400:])
    check('role="status"' in page and "not-the-password" not in page, "no result line, or the typed password came back")
    check('name="password"' in page and not re.search(r'name="password"[^>]*value="[^"]', page), "the password field isn't empty")
    check(('value="%s"' % label) in page, "the typed label wasn't kept")
    check(label not in flat(admin_get(admin)), "a login that failed was saved")

    page = post_form(admin, "save", label=label)
    cid = created_id(page, label)
    text = flat(page)
    check(("Shared login \"%s\" saved." % label) in text, "no success message: %s" % text[:600])
    check(re.search(r"%s ppa_other vault_rot read-only not shared yet" % re.escape(label), text), "not listed: %s" % text[:1200])
    check(ROT_PASSWORD not in page, "the password is in the page")
    audit = vault_php('echo $db->query("SELECT action || detail FROM audit_log WHERE credential_id = " . $db->quote(%s))->fetchColumn();' % php_str(cid))
    check(audit == 'login_saved{"kind":"shared"}', "audit: %r" % audit)


@test
def test_test_only_saves_nothing():
    label = uniq("test-only")
    admin = boss()
    page = post_form(admin, "test", label=label)
    text = flat(page)
    check("Connection test passed: logged in to ppa_other as vault_rot." in text, "no pass line: %s" % text[-500:])
    check(label not in flat(admin_get(admin)), "test connection only saved the login")
    page = post_form(admin, "test", label=label, password="nope-nope")
    check("Connection test passed" not in flat(page), "a wrong password passed")


@test
def test_edit_blank_password_keeps_it():
    label = uniq("keep-pw")
    cid = rot_shared(label, [("user", "keeper", None)])
    admin = boss()
    page = post_form(admin, "save", cid, label=label + "-renamed", password="")
    check(("Shared login \"%s-renamed\" saved." % label) in flat(page), "no success: %s" % flat(page)[:600])
    check(login_ok("keeper", cid), "the login stopped working after a label-only edit")
    # Changing only the access tag and the database to the other allowed one keeps working too once re-typed.
    page = post_form(admin, "test", cid, label=label, password="")
    check("Connection test passed" in flat(page), "the stored password wasn't used for the test: %s" % flat(page)[-400:])


@test
def test_changing_user_needs_password():
    label = uniq("chg-user")
    cid = rot_shared(label)
    admin = boss()
    page = post_form(admin, "save", cid, label=label, pg_username="postgres", password="")
    check("needs the password again" in flat(page), "no needs-password error: %s" % flat(page)[-500:])
    row = vault_php('$r = $db->query("SELECT pg_username FROM credentials WHERE id = " . $db->quote(%s))->fetchColumn(); echo $r;' % php_str(cid))
    check(row == ROT_USER, "the username changed: %r" % row)


@test
def test_per_database_server_rejects_other_db():
    admin = boss()
    admin.get("intro.php")
    label = uniq("wrong-db")
    page = post_form(admin, "save", label=label, database="ppa_test_nope")
    check("only allows these databases: ppa_other, ppa_test" in flat(page), "no error: %s" % flat(page)[-500:])
    check(label not in flat(admin_get(admin)), "saved on a database the server doesn't allow")


@test
def test_share_form_defaults_to_user():
    cid = rot_shared(uniq("usr-default"))
    page = admin_get(boss(), id=cid)
    radios = re.findall(r'<input type="radio" name="type" value="(\w+)"[^>]*?( checked="checked")?\s*/>', page)
    check(radios == [("user", " checked=\"checked\""), ("group", "")], "share radios: %r" % radios)
    check(re.search(r'<label for="vault-principal">User name</label>', page), "the name field isn't labelled for a user")
    m = re.search(r'<input type="text" id="vault-principal"[^>]*>', page)
    check(m and 'list="vault-principals-user"' in m.group(0), "the name field doesn't suggest users: %s" % (m.group(0) if m else ""))
    # After a failed group share, the form keeps the group choice
    page = share_via_page(boss(), cid, "group", "")
    m = re.search(r'<input type="text" id="vault-principal"[^>]*>', page)
    check(m and 'list="vault-principals-group"' in m.group(0), "a failed group share lost the choice")


@test
def test_database_field_follows_server():
    admin = boss()
    # A per-database server: a select of just its databases
    page = post_form(admin, "test", label=uniq("dbfield"), database="ppa_test", password="wrong")
    m = re.search(r'<select id="vault-database" name="database"[^>]*>(.*?)</select>', page, re.S)
    check(m, "no Database select for a per-database server")
    check(re.findall(r'<option value="([^"]*)"', m.group(1)) == ["ppa_other", "ppa_test"], "options: %s" % m.group(1))
    check('<option value="ppa_test" selected="selected">' in m.group(1), "the posted database isn't selected")
    check("<datalist" not in re.sub(r'<datalist id="vault-principals-(user|group)">', "", page), "a browser suggestion list is left")
    # Any other server: a text box with what was typed
    page = post_form(admin, "test", label=uniq("dbfield"), server_id="test", database="postgres", password="wrong")
    m = re.search(r'<input type="text" id="vault-database" name="database"[^>]*>', page)
    check(m and 'value="postgres"' in m.group(0) and "list=" not in m.group(0), "no plain text box: %s" % (m.group(0) if m else page[-300:]))
    # Each server option says what the field should become
    check('data-dbs="[&quot;ppa_other&quot;,&quot;ppa_test&quot;]"' in page, "the scoped option has no database list")
    check(re.search(r'<option value="test" data-dbs="\[\]" data-default-db="postgres"', page), "the test option has no default database")


@test
def test_edit_form_never_prefills_password():
    cid = rot_shared(uniq("noprefill"))
    page = form_page(boss(), cid)
    m = re.search(r'<input[^>]*name="password"[^>]*>', page)
    check(m, "no password input")
    check("value=" not in m.group(0), "the password input has a value: %s" % m.group(0))
    check('placeholder="Leave blank to keep the current password"' in m.group(0), "no placeholder")
    check(ROT_PASSWORD not in page, "the password is in the edit page")
    text = flat(page)
    for want in ("Edit shared login", "Test and save", "Test connection only", "Postgres username", "Access tag",
                 "Env and UI servers. The login belongs to this server and is deleted with it.",
                 "Saving always tests the connection first. A login that fails is not saved."):
        check(want in text, "missing %r" % want)
    check("New shared login" in flat(form_page(boss())), "no New shared login title")


@test
def test_shared_form_is_admin_only_and_post_only():
    cid = rot_shared(uniq("form-guard"))
    status, page = who(uniq("alice"), "dba").get("vault_admin.php", action="edit", id=cid)
    check(status == 403, "a non-admin got HTTP %s on the form" % status)
    admin = boss()
    label = uniq("get-save")
    admin_get(admin, action="save", server_id="scoped", database="ppa_other", label=label, pg_username=ROT_USER, password=ROT_PASSWORD)
    check(label not in flat(admin_get(admin)), "a GET saved a login")

# --- Manage servers (boards 6 and 7): servers_admin.php

def srv_get(c, **params):
    return c.get("servers_admin.php", **params)[1]


def drop_servers(*keys):
    """Removes UI servers (and their logins) left by an earlier run, straight from the vault."""
    for key in keys:
        vault_php('$db->prepare("DELETE FROM servers WHERE \\"key\\" = ? AND source = \'ui\'")->execute(array(%s));' % php_str(key))


def server_fields(key, **over):
    f = {"newkey": key, "name": "Name of " + key, "host": "db", "port": "5432", "sslmode": "disable",
         "default_db": "ppa_other", "enabled": "1"}
    f.update(over)
    return f


def srv_post(admin, action, fields, **params):
    """Posts like the form: the page first (for the token), then the POST."""
    srv_get(admin, **({"action": "add"} if action in ("save", "test") else {}))
    return admin.post("servers_admin.php", dict(fields, action=action, **params))[1]


def add_server(admin, key, **over):
    page = srv_post(admin, "save", server_fields(key, **over))
    check("added." in flat(page), "adding %s: %s" % (key, flat(page)[-300:]))
    return page


def tree_text(c):
    return c.get("servers.php", action="tree")[1]


def server_row(key):
    out = vault_php('$st = $db->prepare("SELECT status, name, host, port, sslmode, source FROM servers WHERE \\"key\\" = ?"); '
                    '$st->execute(array(%s)); echo json_encode($st->fetch(PDO::FETCH_ASSOC));' % php_str(key))
    return json.loads(out) or None


@test
def test_servers_admin_non_admin_403():
    c = who(uniq("alice"), "dba")
    for params in ({}, {"action": "add"}, {"action": "edit", "key": "test"}, {"action": "delete", "key": "test"}):
        status, page = c.get("servers_admin.php", **params)
        check(status == 403, "a non-admin got HTTP %s for %r" % (status, params))
    status, page = c.post("servers_admin.php", {"action": "save", **server_fields("nope-admin")})
    check(status == 403, "a non-admin POST got HTTP %s" % status)
    check('href="servers_admin.php"' not in c.get("intro.php")[1], "the Manage servers tab is shown to a non-admin")
    check('href="servers_admin.php"' in boss().get("intro.php")[1], "no Manage servers tab for an admin")


@test
def test_servers_list_env_and_counts():
    admin = boss()
    drop_servers("list-ui")
    add_server(admin, "list-ui", host="db", sslmode="prefer", name="List UI")
    page = srv_get(admin)
    text = flat(page)
    for name in ("Test", "Scoped", "Tls", "List UI"):
        check(name in text, "%s isn't in the server list" % name)
    check("Env servers are read-only here. Change them in the env and restart the app." in text, "no env note")
    check("Edit in env" in text and "+ Add server" in text, "no 'Edit in env' / '+ Add server'")
    row = re.search(r'<tr[^>]*>(?:(?!</tr>).)*List UI(?:(?!</tr>).)*</tr>', page, re.S)
    check(row and "Disable" in row.group(0) and "Delete" in row.group(0) and "none" in row.group(0), "UI row actions: %r" % (row and flat(row.group(0))))
    drop_servers("list-ui")


@test
def test_add_server_shows_in_tree():
    admin = boss()
    drop_servers("extra-db")
    name = "Extra DB " + uuid.uuid4().hex[:6]
    add_server(admin, "extra-db", name=name, host="db", port="5432", sslmode="disable", default_db="ppa_other")
    check(name in tree_text(who(uniq("alice"), "dba")), "the new server isn't in alice's tree")
    check(server_row("extra-db")["source"] == "ui", "the row isn't a UI row")
    audit = vault_php('echo $db->query("SELECT COUNT(*) FROM audit_log WHERE action = \'server_added\' AND server_id = \'extra-db\'")->fetchColumn();')
    check(int(audit) >= 1, "no server_added audit row")
    drop_servers("extra-db")


@test
def test_add_rejects_env_key():
    admin = boss()
    page = srv_post(admin, "save", server_fields("test", host="elsewhere.example"))
    check("already uses this key" in flat(page), "no key error: %s" % flat(page)[-300:])
    check(server_row("test")["host"] != "elsewhere.example", "the env row changed")


@test
def test_add_rejects_same_host_port_ssl():
    admin = boss()
    drop_servers("dup-tls")
    page = srv_post(admin, "save", server_fields("dup-tls", host="db", port="5432", sslmode="require"))
    check("Tls already uses this host, port and SSL mode." in flat(page), "no duplicate error naming Tls: %s" % flat(page)[-300:])
    check(server_row("dup-tls") is None, "the duplicate was saved")


@test
def test_add_rejects_bad_fields():
    admin = boss()
    drop_servers("bad-one")
    for over in ({"port": "70000"}, {"host": "a b"}, {"sslmode": "allow"}, {"name": ""}, {"default_db": ""}):
        page = srv_post(admin, "save", server_fields("bad-one", **over))
        check("added." not in flat(page), "%r was accepted" % (over,))
    check(server_row("bad-one") is None, "a bad server was saved")
    check(server_row("Bad Key") is None and "added." not in flat(srv_post(admin, "save", server_fields("Bad Key"))), "a bad key was accepted")


@test
def test_env_server_read_only():
    admin = boss()
    before = server_row("test")
    page = srv_post(admin, "save", server_fields("test", name="Hacked"), key="test")
    check("comes from the env" in flat(page), "no read-only error: %s" % flat(page)[-300:])
    check(server_row("test") == before, "the env row changed")
    status, page = admin.get("servers_admin.php", action="edit", key="test")
    check("comes from the env" in flat(page), "editing an env server opened a form")
    page = srv_post(admin, "disable", {}, key="test")
    check(server_row("test")["status"] == "active", "an env server was disabled")
    page = srv_post(admin, "dodelete", {"confirm": "test"}, key="test")
    check(server_row("test") is not None, "an env server was deleted")


@test
def test_edit_server_changes_fields():
    admin = boss()
    drop_servers("edit-me")
    add_server(admin, "edit-me")
    page = srv_get(admin, action="edit", key="edit-me")
    check('value="edit-me"' in page and 'readonly="readonly"' in page, "the key isn't read-only on edit")
    page = srv_post(admin, "save", server_fields("edit-me", name="Renamed server", sslmode="prefer"), key="edit-me")
    check("saved." in flat(page), "edit: %s" % flat(page)[-300:])
    row = server_row("edit-me")
    check(row["name"] == "Renamed server" and row["sslmode"] == "prefer", "row is %r" % row)
    changed = vault_php('echo $db->query("SELECT detail FROM audit_log WHERE action = \'server_changed\' AND server_id = \'edit-me\' ORDER BY id DESC LIMIT 1")->fetchColumn();')
    check("Renamed server" in changed, "no server_changed audit detail: %r" % changed)
    drop_servers("edit-me")


@test
def test_server_with_logins_keeps_its_address():
    admin = boss()
    drop_servers("pinned-db")
    add_server(admin, "pinned-db", name="Pinned " + uuid.uuid4().hex[:6], sslmode="disable")
    alice = Client(SSO, "db:5432:disable", identity=(uniq("alice"), "dba"))
    status, page = alice.login(ROT_USER, ROT_PASSWORD, extra={"loginSave": "on", "loginSaveLabel": uniq("pinned")})
    check(status == 200 and "loginUsername" not in page, "alice couldn't log in to the UI server (HTTP %s)" % status)
    logout(alice, "db:5432:disable")
    refused = "This server has saved logins, so its host and port can't be changed"
    for over in ({"host": "elsewhere.example"}, {"port": "6432"}):
        page = srv_post(admin, "save", server_fields("pinned-db", **over), key="pinned-db")
        check(refused in flat(page), "%r was not refused: %s" % (over, flat(page)[-300:]))
    row = server_row("pinned-db")
    check((row["host"], int(row["port"]), row["sslmode"]) == ("db", 5432, "disable"), "the row changed: %r" % row)
    page = srv_post(admin, "save", server_fields("pinned-db", sslmode="verify-full"), key="pinned-db")
    check("saved." in flat(page) and server_row("pinned-db")["sslmode"] == "verify-full", "a stricter SSL mode was refused: %s" % flat(page)[-300:])
    page = srv_post(admin, "save", server_fields("pinned-db", sslmode="require"), key="pinned-db")
    check(refused in flat(page) and server_row("pinned-db")["sslmode"] == "verify-full", "a weaker SSL mode was accepted")
    drop_servers("pinned-db")


@test
def test_test_connection_not_saved():
    admin = boss()
    drop_servers("probe-db")
    fields = server_fields("probe-db", sslmode="disable", default_db="ppa_other")
    page = srv_post(admin, "test", dict(fields, test_user=ROT_USER, test_password=ROT_PASSWORD))
    check("Reached db:5432." in flat(page) and "Login worked." in flat(page), "no success line: %s" % flat(page)[-300:])
    check(ROT_PASSWORD not in page, "the page holds the test password")
    page = srv_post(admin, "test", dict(fields, test_user=ROT_USER, test_password="wrong-" + ROT_PASSWORD))
    check("Login worked" not in flat(page) and 'class="message error"' in page, "a wrong password passed the test")
    check("wrong-" + ROT_PASSWORD not in page, "the page holds the wrong test password")
    check(server_row("probe-db") is None, "testing saved the server")
    dump = vault_php('foreach (array("servers", "credentials", "audit_log") as $t) { '
                     'foreach ($db->query("SELECT * FROM $t")->fetchAll(PDO::FETCH_ASSOC) as $r) echo json_encode($r, JSON_PARTIAL_OUTPUT_ON_ERROR); }')
    check(ROT_PASSWORD not in dump and ROT_PASSWORD not in dump.replace("\\", ""), "the vault holds the test password")


@test
def test_disable_hides_server_and_logins():
    admin = boss()
    drop_servers("hide-db")
    name = "Hide DB " + uuid.uuid4().hex[:6]
    add_server(admin, "hide-db", name=name)
    alice = Client(SSO, "db:5432:disable", identity=(uniq("alice"), "dba"))
    label = uniq("hide")
    status, page = alice.login(ROT_USER, ROT_PASSWORD, extra={"loginSave": "on", "loginSaveLabel": label})
    check(status == 200 and "loginUsername" not in page, "alice couldn't log in to the UI server (HTTP %s)" % status)
    logout(alice, "db:5432:disable")
    check(label in flat(my_page(alice)), "alice's login isn't on her page")
    check(name in tree_text(alice), "the server isn't in the tree")
    srv_post(admin, "disable", {}, key="hide-db")
    check(server_row("hide-db")["status"] == "disabled", "the server wasn't disabled")
    check(name not in tree_text(alice), "a disabled server is in the tree")
    check(label not in flat(my_page(alice)), "a login on a disabled server is on her page")
    page = srv_get(admin)
    check("disabled" in flat(page) and "Enable" in page, "the list doesn't show the server disabled")
    srv_post(admin, "enable", {}, key="hide-db")
    check(name in tree_text(alice), "the enabled server isn't back in the tree")
    check(label in flat(my_page(alice)), "her login didn't come back")
    status, page = admin.get("servers_admin.php", action="disable", key="hide-db")
    check(server_row("hide-db")["status"] == "active", "a GET disabled the server")
    drop_servers("hide-db")


@test
def test_delete_needs_typed_key_and_cascades():
    admin = boss()
    drop_servers("gone-db")
    name = "Gone DB " + uuid.uuid4().hex[:6]
    add_server(admin, "gone-db", name=name)
    alice = Client(SSO, "db:5432:disable", identity=(uniq("alice"), "dba"))
    label = uniq("gone")
    alice.login(ROT_USER, ROT_PASSWORD, extra={"loginSave": "on", "loginSaveLabel": label})
    logout(alice, "db:5432:disable")
    check(label in flat(my_page(alice)), "alice's login wasn't saved")
    cid = vault_php('echo $db->query("SELECT id FROM credentials WHERE server_id = \'gone-db\'")->fetchColumn();')
    page = srv_get(admin, action="delete", key="gone-db")
    text = flat(page)
    check("1 saved login (owned by 1 person)" in text and "People lose access right away." in text, "dialog text: %s" % text[-400:])
    check(label not in text and ROT_USER not in text, "the dialog names a personal login")
    check('data-key="gone-db"' in page and "Type the server key to confirm" in text, "no typed-key input")
    check('data-ppa-dialog="modal"' in srv_get(admin) and "action=delete&amp;key=gone-db" in srv_get(admin), "no delete dialog link")
    page = admin.post("servers_admin.php", {"action": "dodelete", "key": "gone-db", "confirm": "wrong"})[1]
    check("That is not the server key" in flat(page), "no wrong-key message")
    check(server_row("gone-db") is not None, "a wrong key deleted the server")
    check(label in flat(my_page(alice)), "a wrong key deleted the login")
    page = admin.post("servers_admin.php", {"action": "dodelete", "key": "gone-db", "confirm": "gone-db"})[1]
    check("deleted, with 1 logins" in flat(page), "no deleted message: %s" % flat(page)[-300:])
    check(server_row("gone-db") is None, "the server is still there")
    check(name not in tree_text(alice), "the deleted server is in the tree")
    check(label not in flat(my_page(alice)), "the login survived")
    detail = vault_php('$st = $db->prepare("SELECT detail FROM audit_log WHERE action = \'credential_deleted\' AND credential_id = ?"); '
                       '$st->execute(array(%s)); echo $st->fetchColumn();' % php_str(cid))
    check("server_deleted" in detail, "no credential_deleted audit row with the reason: %r" % detail)
    n = vault_php('echo $db->query("SELECT COUNT(*) FROM credentials WHERE server_id = \'gone-db\'")->fetchColumn();')
    check(n == "0", "credentials remain")


@test
def test_delete_get_never_deletes():
    admin = boss()
    drop_servers("keep-db")
    add_server(admin, "keep-db")
    admin.get("servers_admin.php", action="dodelete", key="keep-db", confirm="keep-db")
    check(server_row("keep-db") is not None, "a GET deleted the server")
    drop_servers("keep-db")


@test
def test_removed_env_server_delete_its_logins():
    admin = boss()
    key = "old-" + uuid.uuid4().hex[:6]
    vault_php('$n = VaultStore::now(); $db->prepare("INSERT INTO servers (\\"key\\", name, source, host, port, sslmode, default_db, status, created_at, updated_at) '
              'VALUES (?, ?, \'env\', \'gone.example\', 5432, \'require\', \'postgres\', \'removed\', ?, ?)")->execute(array(%s, %s, $n, $n));' % (php_str(key), php_str("Old " + key)))
    page = srv_get(admin)
    check("Delete its logins" in page and "removed from env" in flat(page), "no removed-env row")
    check("Delete its logins" in flat(page), "no action")
    admin.post("servers_admin.php", {"action": "dodelete", "key": key, "confirm": key})
    check(server_row(key) is None, "the removed env row wasn't deleted")


@test
def test_servers_allow_ui_off():
    """The local-mode app runs with SERVERS_ALLOW_UI=false."""
    c = admin_client()
    page = c.get("servers_admin.php")[1]
    check("+ Add server" not in page, "the Add server button is shown with SERVERS_ALLOW_UI=false")
    check("Edit in env" in page, "the list didn't open")
    for params in ({"action": "add"}, {"action": "edit", "key": "test"}):
        status, page = c.get("servers_admin.php", **params)
        check(status == 403, "%r answered HTTP %s" % (params, status))
    for action in ("save", "test", "enable", "disable"):
        c.get("servers_admin.php")
        status, page = c.post("servers_admin.php", dict(server_fields("off-ui"), action=action, key="test"))
        check(status == 403, "POST %s answered HTTP %s" % (action, status))
    # Deleting a server removed from the env stays allowed.
    key = "old-" + uuid.uuid4().hex[:6]
    vault_php('$n = VaultStore::now(); $db->prepare("INSERT INTO servers (\\"key\\", name, source, host, port, sslmode, default_db, status, created_at, updated_at) '
              'VALUES (?, ?, \'env\', \'gone.example\', 5432, \'require\', \'postgres\', \'removed\', ?, ?)")->execute(array(%s, %s, $n, $n));' % (php_str(key), php_str("Old " + key)),
              service="app_local")
    page = c.get("servers_admin.php")[1]
    check("Delete its logins" in page, "no 'Delete its logins' with SERVERS_ALLOW_UI=false")
    c.post("servers_admin.php", {"action": "dodelete", "key": key, "confirm": key})
    check(key not in c.get("servers_admin.php")[1], "the removed env server wasn't deleted with SERVERS_ALLOW_UI=false")
    # A server added in the UI earlier (while it was allowed) is off: not in
    # the tree, and nobody can log in to it. It stays listed, and deletable.
    key = uniq("ui-off")
    name = "UI off " + uuid.uuid4().hex[:6]
    vault_php('$n = VaultStore::now(); $db->prepare("INSERT INTO servers (\\"key\\", name, source, host, port, sslmode, default_db, status, created_at, updated_at) '
              'VALUES (?, ?, \'ui\', \'db\', 5432, \'disable\', \'ppa_other\', \'active\', ?, ?)")->execute(array(%s, %s, $n, $n));' % (php_str(key), php_str(name)),
              service="app_local")
    check(name not in tree_text(c), "a UI server is in the tree with SERVERS_ALLOW_UI=false")
    off = Client(LOCAL, "db:5432:disable", identity=None)
    signin(off, "admin", ADMIN_PASSWORD)
    status, page = off.login(ROT_USER, ROT_PASSWORD)
    check("invalid server parameter" in page and "loginUsername" not in page, "logged in to a UI server: %s" % flat(page)[-300:])
    page = c.get("servers_admin.php")[1]
    check(name in page, "the UI server isn't listed")
    c.post("servers_admin.php", {"action": "dodelete", "key": key, "confirm": key})
    check(key not in c.get("servers_admin.php")[1], "the UI server wasn't deleted with SERVERS_ALLOW_UI=false")


def main(sso_base, local_base, strict_base, filter=None):
    global SSO, LOCAL, STRICT
    SSO, LOCAL, STRICT = sso_base, local_base, strict_base
    failures = 0
    for fn in TESTS:
        if filter and filter not in fn.__name__:
            continue
        try:
            fn()
            print("ok    " + fn.__name__)
        except Failure as e:
            failures += 1
            print("FAIL  %s: %s" % (fn.__name__, e))
        except Exception:
            failures += 1
            print("FAIL  %s: error\n%s" % (fn.__name__, traceback.format_exc()))
    print("%d failures" % failures)
    return 1 if failures else 0


if __name__ == "__main__":
    if len(sys.argv) < 4:
        sys.exit(__doc__)
    sys.exit(main(*sys.argv[1:5]))

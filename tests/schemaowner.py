#!/usr/bin/env python3
"""
Check the Owner list of the schema forms against a running phpPgAdmin.

The list holds the roles the session can act as (NOLOGIN roles included),
not the login roles, and defaults to the role the session runs as. Uses the
owner model set up in fixtures.sql: database ppa_owned, owned by the NOLOGIN
role ppa_owned_owner, whose member app runs as it in ppa_owned.

    python3 tests/schemaowner.py http://127.0.0.1:8080 db:5432:allow ppa ppa
"""

import html
import re
import sys

from security import Client

OWNED = "ppa_owned"
SELECT = re.compile(r'<select name="(formAuth|owner)">(.*?)</select>', re.S)
OPTION = re.compile(r'<option value="([^"]*)"( selected="selected")?')


def owner_select(page):
    """The Owner <select> of a form: (all option values, the selected one)."""
    m = SELECT.search(page)
    if not m:
        return None, None
    options = [(html.unescape(v), bool(s)) for v, s in OPTION.findall(m.group(2))]
    selected = [v for v, s in options if s]
    return [v for v, _ in options], selected[0] if selected else None


def main(base, server, user, password):
    failures = []

    def check(ok, what):
        print(("ok    " if ok else "FAIL  ") + what)
        if not ok:
            failures.append(what)

    def create_form(c, database):
        _, page = c.get("schemas.php", server=server, database=database, subject="database", action="create")
        return page

    # The superuser can give a schema to any role, NOLOGIN ones too.
    su = Client(base, server)
    _, page = su.login(user, password)
    check("loginUsername" not in page, "superuser login works")
    roles, selected = owner_select(create_form(su, "ppa_test"))
    check(roles is not None, "create form has an Owner list")
    roles = roles or []
    check("ppa_owned_owner" in roles and "staff" in roles,
          "superuser's Owner list has the NOLOGIN roles, got %s" % roles)
    check(not any(r.startswith("pg_") for r in roles), "Owner list leaves out the pg_ roles, got %s" % roles)
    check(selected == user, "superuser's Owner list defaults to %s, got %s" % (user, selected))

    # A login whose sessions in ppa_owned run as ppa_owned_owner.
    app = Client(base, server)
    _, page = app.login("app", "app")
    check("loginUsername" not in page, "app login works")
    roles, selected = owner_select(create_form(app, OWNED))
    roles = roles or []
    check(selected == "ppa_owned_owner", "app's Owner list defaults to ppa_owned_owner, got %s" % selected)
    check(user not in roles and "staff" not in roles,
          "app's Owner list has only roles it can act as, got %s" % roles)

    # Creating with the default owner works and gives the schema to the role.
    _, page = app.post("schemas.php", {
        "action": "create", "server": server, "database": OWNED, "subject": "database",
        "formName": "ppv_report", "formAuth": selected or "", "formComment": "", "create": "Create",
    })
    check("must be able to SET ROLE" not in page, "create schema as app works")
    owner = app.scalar("SELECT nspowner::regrole FROM pg_namespace WHERE nspname = 'ppv_report'", OWNED)
    check(owner == "ppa_owned_owner", "ppv_report belongs to ppa_owned_owner, got %s" % owner)

    # The alter form keeps the current owner selected, even one app can't act as.
    for schema, expected in (("ppv_report", "ppa_owned_owner"), ("public", None)):
        _, page = app.get("schemas.php", server=server, database=OWNED, subject="schema",
                          schema=schema, action="alter")
        roles, selected = owner_select(page)
        if expected is None:
            expected = app.scalar("SELECT nspowner::regrole FROM pg_namespace WHERE nspname = 'public'", OWNED)
        check(selected == expected, "alter form for %s selects owner %s, got %s" % (schema, expected, selected))
        check(roles is not None and len(roles) == len(set(roles)),
              "alter form for %s lists each owner once, got %s" % (schema, roles))

    su.sql("DROP SCHEMA IF EXISTS ppv_report", OWNED)

    print("%d failures" % len(failures))
    return 1 if failures else 0


if __name__ == "__main__":
    if len(sys.argv) != 5:
        sys.exit(__doc__)
    sys.exit(main(*sys.argv[1:]))

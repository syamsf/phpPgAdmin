#!/usr/bin/env python3
"""
The SQL editor asks before running a DELETE without WHERE or a TRUNCATE.

    python3 tests/sqlguard.py http://127.0.0.1:8080 db:5432:allow ppa ppa [test ...]
"""

import html
import re
import sys
import traceback

from security import Client, Failure, check

DB = "ppa_test"
TABLE = "public.ppa_sqlguard"
TESTS = []


def test(fn):
    TESTS.append(fn)
    return fn


def run(c, query, **extra):
    """Posts a query to sql.php like the editor does; returns the page."""
    if c.token is None:
        c.get("database.php", server=c.server, database=DB, subject="database", action="sql")
    data = {"server": c.server, "database": DB, "query": query}
    data.update(extra)
    return c.post("sql.php", data)[1]


def rows(c):
    return int(c.scalar("SELECT count(*) FROM %s" % TABLE))


def reset(c):
    page = run(c, "DROP TABLE IF EXISTS %s; CREATE TABLE %s (id int); INSERT INTO %s SELECT generate_series(1, 3)"
               % (TABLE, TABLE, TABLE))
    check("SQL executed" in page, "setup failed")
    check(rows(c) == 3, "setup has 3 rows")


def asks(page):
    return "Run this query?" in page and 'name="ppa_run_unsafe"' in page


def hidden(page, name):
    m = re.search(r'<form action="sql.php" method="post" class="sql-unsafe-form">.*?</form>', page, re.S)
    check(m, "no Run anyway form")
    f = re.search(r'name="%s" value="([^"]*)"' % re.escape(name), m.group(0))
    return html.unescape(f.group(1)) if f else None


@test
def test_delete_without_where_asks_first(c):
    reset(c)
    page = run(c, "DELETE FROM %s" % TABLE)
    check(asks(page), "no question for a DELETE without WHERE")
    check("<code>DELETE FROM %s</code>" % TABLE in page, "the statement is shown")
    check("Don&#039;t ask again in this browser tab" in page or "Don't ask again in this browser tab" in page, "tab box shown")
    check('id="sql-editor-form"' in page, "the editor is there to add a WHERE")
    check(rows(c) == 3, "nothing deleted before the answer")
    # Run anyway posts the same query with ppa_run_unsafe
    check(hidden(page, "query") == "DELETE FROM %s" % TABLE, "Run anyway carries the query")
    page = run(c, hidden(page, "query"), ppa_run_unsafe="1")
    check("SQL executed" in page and not asks(page), "Run anyway runs it")
    check(rows(c) == 0, "rows deleted after Run anyway")


@test
def test_truncate_asks_first(c):
    reset(c)
    page = run(c, "-- clean up\ntruncate %s" % TABLE)
    check(asks(page), "no question for TRUNCATE")
    check(rows(c) == 3, "nothing truncated before the answer")
    run(c, "truncate %s" % TABLE, ppa_run_unsafe="1")
    check(rows(c) == 0, "truncated after Run anyway")


@test
def test_delete_with_where_runs_at_once(c):
    reset(c)
    page = run(c, "DELETE FROM %s WHERE id = 1" % TABLE)
    check(not asks(page) and "SQL executed" in page, "a DELETE with WHERE runs without asking")
    check(rows(c) == 2, "one row deleted")


@test
def test_only_explain_analyze_asks(c):
    reset(c)
    page = run(c, "DELETE FROM %s" % TABLE, explain="Explain")
    check(not asks(page), "plain EXPLAIN runs nothing, so it doesn't ask")
    check(rows(c) == 3, "EXPLAIN deleted nothing")
    page = run(c, "DELETE FROM %s" % TABLE, explain_analyze="Explain analyze")
    check(asks(page), "EXPLAIN ANALYZE really deletes, so it asks")
    check(hidden(page, "explain_analyze") is not None and hidden(page, "query") == "DELETE FROM %s" % TABLE,
          "Run anyway keeps EXPLAIN ANALYZE without doubling it")
    check(rows(c) == 3, "nothing deleted before the answer")


@test
def test_selection_and_editor_text_are_kept(c):
    reset(c)
    full = "SELECT 1;\nDELETE FROM %s;" % TABLE
    page = run(c, "DELETE FROM %s;" % TABLE, sqleditor_text=full, sqleditor_selection="1:0:1:30")
    check(asks(page), "running only the DELETE line asks")
    check(hidden(page, "sqleditor_text") == full and hidden(page, "sqleditor_selection") == "1:0:1:30",
          "Run anyway keeps the editor text and selection")
    check(html.escape(full, quote=False) in page, "the editor shows the whole text again")


@test
def test_get_never_runs_it(c):
    reset(c)
    c.get("sql.php", server=c.server, database=DB, query="DELETE FROM %s" % TABLE, ppa_run_unsafe="1")
    check(rows(c) == 3, "a GET with ppa_run_unsafe deletes nothing")


def main(base, server, user, password):
    only = set(sys.argv[5:])
    failures = 0
    for fn in TESTS:
        if only and fn.__name__ not in only:
            continue
        c = Client(base, server)
        try:
            status, page = c.login(user, password)
            check(status == 200 and "loginUsername" not in page, "login failed (HTTP %s)" % status)
            fn(c)
            print("ok    " + fn.__name__)
        except Failure as e:
            failures += 1
            print("FAIL  %s: %s" % (fn.__name__, e))
        except Exception:
            failures += 1
            print("FAIL  %s: error\n%s" % (fn.__name__, traceback.format_exc()))
    try:
        c = Client(base, server)
        c.login(user, password)
        run(c, "DROP TABLE IF EXISTS %s" % TABLE)
    except Exception:
        pass
    print("%d failures" % failures)
    return 1 if failures else 0


if __name__ == "__main__":
    if len(sys.argv) < 5:
        sys.exit(__doc__)
    sys.exit(main(*sys.argv[1:5]))

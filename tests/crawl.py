#!/usr/bin/env python3
"""
Log in to a running phpPgAdmin and click through every page we can reach.

Fails if a page returns 5xx, prints a PHP error, or shows an SQL error.
PHP warnings that only go to the log are checked by run.sh, not here.

    python3 tests/crawl.py http://127.0.0.1:8080 db:5432:allow ppa ppa
"""

import hashlib
import html
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from collections import Counter, deque
from http.cookiejar import CookieJar

MAX_PAGES = 2000
MAX_PER_ACTION = 6

# Actions that change something even on GET, or that would log us out.
SKIP_ACTION = re.compile(
    r"^(drop|del|delete|empty|signal|logout|clear|vacuum|analyze|cluster|reindex"
    r"|nextval|setval|reset|restart|enable|disable|grant|revoke|save|add_|import)"
)
SKIP_PAGE = {"logout.php", "help.php", "redirect.php"}

PAGE_ERRORS = re.compile(
    r"(<b>(Fatal error|Parse error|Warning|Notice|Deprecated)</b>:"
    r"|Fatal error: |Uncaught |SQL error:)"
)
# For pages where an SQL error is what we're testing.
PHP_ERRORS = re.compile(
    r"(<b>(Fatal error|Parse error|Warning|Notice|Deprecated)</b>:"
    r"|Fatal error: |Uncaught )"
)

LINK = re.compile(r"""(?:href|src|action)\s*=\s*["']([^"'#]+)""", re.I)


def main(base, server, user, password):
    base = base.rstrip("/") + "/"
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(CookieJar()))
    opener.addheaders += [("Remote-User", "ppa-test"), ("Remote-Groups", "role-admin")]

    token = {}

    def fetch(url, data=None):
        # Like a browser: a POST carries the token of the last page seen.
        if data is not None and token.get("v") and "ppa_csrf" not in data:
            data = dict(data, ppa_csrf=token["v"])
        body = urllib.parse.urlencode(data).encode() if data is not None else None
        try:
            with opener.open(url, body, timeout=60) as resp:
                status, page = resp.status, resp.read().decode("utf-8", "replace")
        except urllib.error.HTTPError as e:
            status, page = e.code, e.read().decode("utf-8", "replace")
        m = re.search(r'<meta name="ppa-csrf" content="([^"]+)"', page)
        if m:
            token["v"] = html.unescape(m.group(1))
        return status, page

    fetch(base + "intro.php")

    status, page = fetch(base + "redirect.php", {
        "subject": "server",
        "server": server,
        "loginServer": server,
        "loginUsername": user,
        "loginPassword_" + hashlib.md5(server.encode()).hexdigest(): password,
        "loginSubmit": "Login",
        # A saved login, so My saved logins has a row and its dialog links.
        "loginSave": "on",
        "loginSaveLabel": "crawl",
    })
    if status != 200 or "loginUsername" in page:
        print("login failed (HTTP %d)" % status)
        print(page[:2000])
        return 1

    q = urllib.parse.quote(server)
    seeds = [
        "intro.php", "browser.php", "servers.php", "servers.php?action=tree", "vault.php",
        "all_db.php?subject=server&server=" + q,
        "roles.php?subject=server&server=" + q,
        "tablespaces.php?subject=server&server=" + q,
        "database.php?subject=database&database=ppa_test&server=" + q,
        "schemas.php?subject=database&database=ppa_test&server=" + q,
        "tables.php?subject=schema&schema=shop&database=ppa_test&server=" + q,
        "tblproperties.php?subject=table&table=orders&schema=shop&database=ppa_test&server=" + q,
        "display.php?subject=table&table=orders&schema=shop&database=ppa_test&server=" + q,
        "display.php?subject=table&table=big&schema=public&database=ppa_test&server=" + q,
        "display.php?subject=table&table=oddities&schema=public&database=ppa_test&server=" + q,
        "display.php?subject=view&view=open_orders&schema=shop&database=ppa_test&server=" + q,
        "fulltext.php?subject=schema&schema=shop&database=ppa_test&server=" + q,
        "history.php?server=" + q + "&database=ppa_test",
        "sqledit.php?action=sql&server=" + q,
        "sqledit.php?action=sql&server=" + q + "&database=ppa_test",
        "sqledit.php?action=find&server=" + q + "&database=ppa_test",
        "database.php?action=sql&subject=database&database=ppa_test&server=" + q,
    ]

    # Things that need a POST or odd parameters, so the crawler would never find them.
    # An optional third item lists text the page must contain; with "SQL error:"
    # among it, an SQL error on the page is expected rather than a failure.
    db = {"server": server, "database": "ppa_test"}
    posts = [
        ("sql.php", dict(db, query="SELECT * FROM shop.orders; SELECT 1/1;", search_path="shop,public"),
         ["SQL executed.", 'class="sql-editor"']),
        ("sql.php", dict(db, query="SELECT *\nFROM shop.orders\nWHERE nope = 1", search_path="shop,public"),
         ["SQL error:", 'data-error-line="3"', "SQL failed."]),
        ("sql.php", dict(db, query="SELECT * FROM shop.orders;", explain="Explain"), ["QUERY PLAN"]),
        ("sql.php", dict(db, query="SELECT count(*) FROM shop.orders", explain_analyze="Explain analyze"),
         ["actual time"]),
        ("sql.php", dict(db, query="SELECT 1 AS one", sqleditor_text="SELECT 0;\nSELECT 1 AS one",
                         sqleditor_selection="1:0:1:15"),
         ['data-selection="1:0:1:15"', "SELECT 0;"]),
        ("sql.php", dict(db, query="SELECT g, repeat('x', 300) AS long FROM generate_series(1, 1500) g"),
         ["sql-rows-capped", "1500", 'class="sql-expand"']),
        ("dataexport.php", dict(db, subject="table", table="orders", schema="shop", what="structureanddata",
                                sd_format="sql", output="show", action="export")),
        ("dataexport.php", dict(db, subject="table", table="customer", schema="shop", what="dataonly",
                                d_format="csv", output="show", action="export")),
        # A table or query the export can't read (here: no such table; in real
        # life usually "permission denied") gives a page with the SQL error,
        # not an HTTP 500 that the browser shows as a broken download.
        ("dataexport.php", dict(db, subject="table", table="no_such_table", schema="shop", what="dataonly",
                                d_format="csv", output="download", action="export"),
         ["SQL error:", "no_such_table", "Export failed."]),
        ("dataexport.php", dict(db, query="SELECT * FROM shop.no_such_table", what="dataonly",
                                d_format="csv", output="download", action="export"),
         ["SQL error:", "no_such_table", "Export failed."]),
        ("dbexport.php", dict(db, subject="database", what="structureanddata", sd_format="sql",
                              output="show", action="export")),
        ("dbexport.php", dict(db, subject="table", table="orders", schema="shop", what="structureonly",
                              s_format="sql", output="show", action="export")),
        ("display.php", dict(db, subject="schema", schema="shop", query="SELECT * FROM shop.customer",
                             action="", strings="collapsed")),
    ]

    failures = []
    seen = set()
    per_action = Counter()
    todo = deque(base + s for s in seeds)
    visited = 0

    def check(url, status, body, errors=PAGE_ERRORS):
        if status >= 500:
            failures.append("%s -> HTTP %d" % (url, status))
            return
        m = errors.search(body)
        if m:
            start = max(0, m.start() - 100)
            snippet = re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", body[start:m.end() + 400]))
            failures.append("%s -> %s" % (url, snippet.strip()))

    for path, data, *rest in posts:
        expect = rest[0] if rest else []
        status, body = fetch(base + path, data)
        name = "POST %s %s" % (path, data.get("subject") or data.get("query", "")[:40])
        check(name, status, body, PHP_ERRORS if "SQL error:" in expect else PAGE_ERRORS)
        for text in expect:
            if text not in body:
                failures.append("%s -> %r not in page" % (name, text))
        if path == "dbexport.php" and "CREATE TABLE" not in body:
            failures.append("POST dbexport.php -> no CREATE TABLE in dump: " + body[:300])

    check_data_grid(fetch, check, failures, base, server)

    while todo and visited < MAX_PAGES:
        url = todo.popleft()
        if url in seen:
            continue
        seen.add(url)

        parts = urllib.parse.urlsplit(url)
        page_name = parts.path.rsplit("/", 1)[-1]
        params = urllib.parse.parse_qs(parts.query)
        action = params.get("action", [""])[0]
        key = (page_name, action, params.get("subject", [""])[0])
        if per_action[key] >= MAX_PER_ACTION:
            continue
        per_action[key] += 1

        status, body = fetch(url)
        visited += 1
        check(url, status, body)

        for link in LINK.findall(body):
            link = urllib.parse.urljoin(url, html.unescape(link))
            p = urllib.parse.urlsplit(link)
            name = p.path.rsplit("/", 1)[-1]
            if not link.startswith(base) or not name.endswith(".php") or name in SKIP_PAGE:
                continue
            act = urllib.parse.parse_qs(p.query).get("action", [""])[0]
            if SKIP_ACTION.match(act):
                continue
            todo.append(urllib.parse.urlunsplit(p._replace(fragment="")))

    print("visited %d pages, %d failures" % (visited, len(failures)))
    for f in failures:
        print("  " + f)

    if visited < 100:
        print("too few pages visited, the crawler probably got stuck")
        return 1
    return 1 if failures else 0


def check_data_grid(fetch, check, failures, base, server):
    """Browsing: row counts and estimates, page size, quick filters, and
    paging through query results with two queries open at once."""
    db = {"server": server, "database": "ppa_test"}

    def get(params, expect=(), reject=()):
        url = base + "display.php?" + urllib.parse.urlencode(dict(db, **params))
        status, body = fetch(url)
        check(url, status, body)
        text = html.unescape(body)
        for e in expect:
            if e not in text:
                failures.append("%s -> expected %r" % (url, e))
        for r in reject:
            if r in text:
                failures.append("%s -> did not expect %r" % (url, r))
        return body

    def table(name, schema="public", **params):
        return dict({"subject": "table", "table": name, "schema": schema}, **params)

    md5 = lambda n: hashlib.md5(str(n).encode()).hexdigest()

    # Big table: planner estimate instead of COUNT(*), unless asked for
    get(table("big"), ["of about 200K", "Count exactly", "page=last"])
    # "Last" without an exact total counts once and opens the last page
    get(table("big", page="last"), ["Rows 199,981–200,000 of 200,000"], ["Count exactly", "Last >>", "rel=\"next\""])
    get(table("big", count="exact"), ["of 200,000", "Last >>"], ["Count exactly"])
    get(table("big", sortkey="2", sortdir="desc", page="3"), ["Rows 61–90 of about 200K"])
    get(table("big", **{"filter[val]": "abc"}), ["Count rows"], ["of about"])
    # Small table: exact count, page size, a page past the end goes to the last one
    get(table("plain", page_size="50"), ["Rows 1–50 of 100", 'aria-current="page"'])
    get(table("plain", page_size="50", page="2"), ["Rows 51–100 of 100"])
    get(table("plain", page_size="25", page="99"), ["Rows 76–100 of 100"])
    get(table("plain", page_size="7"))
    # Quick filters: contains, exact (=), LIKE wildcards taken literally, unknown column
    n = sum(1 for i in range(1, 101) if "c4ca" in md5(i))
    get(table("plain", page_size="25", **{"filter[val]": "c4ca"}),
        ["Rows 1–%d of %d" % (n, n), "Clear filters"])
    get(table("plain", **{"filter[id]": "=42"}), ["Rows 1–1 of 1", md5(42)])
    get(table("oddities", **{"filter[label]": "%_"}), ["No rows found."])
    get(table("oddities", **{"filter[label]": "0% u"}), ["Rows 1–1 of 1", "100% under_score"])
    get(table("plain", **{"filter[nope]": "x", "filter[val]": ""}), ["Rows 1–"])
    # NULL, empty string, timestamps keep fractions and time zone, clipped text copyable
    body = get(table("oddities"), [".345678+00", "12.345678", "END\""])
    for marker in ('<span class="null">NULL</span>', '<span class="empty">empty</span>'):
        if marker not in body:
            failures.append("oddities -> expected %r" % marker)
    # A view: no count up front
    get({"subject": "view", "view": "open_orders", "schema": "shop"}, ["Count rows"])
    # SELECT browse (as from the table's Select form)
    get(table("plain", query="SELECT * FROM public.plain WHERE id > 10", page="2", page_size="25"),
        ["Rows 26–50", "qt="])
    # A long SELECT from the table's query box (a list of 1,500 keys) pages
    # through its qt token only: with the SQL in every link, proxies answer
    # 414 Request-URI Too Large.
    ids = ", ".join("'%09d'" % (31000000 + i) for i in range(1500))
    long_sql = "SELECT * FROM public.plain WHERE id <= 60 OR val IN (%s)" % ids
    status, body = fetch(base + "display.php", dict(db, **table("plain", query=long_sql, page="1", page_size="25")))
    check("POST display.php long SELECT", status, body)
    m = re.search(r'href="(display\.php\?[^"]*page=2)"', body)
    if not m:
        failures.append("POST display.php long SELECT -> no page 2 link")
    else:
        link = html.unescape(m.group(1))
        if "query=" in link or "qt=" not in link or len(link) > 1024:
            failures.append("POST display.php long SELECT -> page 2 link carries the SQL (%d bytes)" % len(link))
        else:
            params = {k: v[0] for k, v in urllib.parse.parse_qs(urllib.parse.urlsplit(link).query).items()}
            get({k: v for k, v in params.items() if k not in db}, ["Rows 26–50"])
    # A token the session doesn't have: say so, not browse the whole table
    get(table("plain", qt="0123456789abcdef"), ["no longer remembered"], ["Rows 1–"])

    # The query box of a table's page takes any query, but Edit and Delete
    # find the row in that table by its key: only for results whose key
    # column comes straight from it.  Else they would open (and save over,
    # or delete) another row of this table that happens to have the same id.
    get(table("big", query="SELECT * FROM public.big WHERE id <= 3"),
        ["action=confeditrow", "action=confdelrow"], ["grid-no-key"])
    for sql in ("SELECT * FROM shop.customer",                                # another table
                "SELECT b.*, c.* FROM public.big b JOIN shop.customer c ON c.id = b.id",  # id twice
                "SELECT id + 0 AS id, val FROM public.big WHERE id <= 3",     # an expression
                "SELECT val FROM public.big WHERE id <= 3"):                  # no key column
        get(table("big", query=sql), ["grid-no-key"], ["action=confeditrow", "action=confdelrow"])

    # No link of a long query's results carries the SQL (Download, Create
    # view, paging...), from a table's query box or from the SQL editor; the
    # Download and Create view pages find it through the token.
    for name, path, data in (
            ("table query box", "display.php", dict(db, **table("plain", query=long_sql, page="1", page_size="25"))),
            ("SQL editor", "sql.php", dict(db, schema="public", query=long_sql, paginate="on", page_size="25"))):
        status, body = fetch(base + path, data)
        check("POST %s long SELECT" % name, status, body)
        links = [html.unescape(l) for l in re.findall(r'href="([^"]+)"', body)]
        long_links = [l for l in links if len(l) > 2048]
        if long_links:
            failures.append("%s long SELECT -> %d links over 2 KB, e.g. %s..." % (name, len(long_links), long_links[0][:120]))
        for target, expect in (("dataexport.php", '31000000'), ("views.php", "31000000")):
            link = next((l for l in links if l.startswith(target + "?") and "qt=" in l), None)
            if link is None:
                failures.append("%s long SELECT -> no %s link with a qt token" % (name, target))
                continue
            status, page = fetch(base + link)
            check(base + link, status, page)
            if expect not in urllib.parse.unquote_plus(html.unescape(page)):
                failures.append("%s long SELECT -> %s doesn't have the query" % (name, target))
    status, page = fetch(base + "dataexport.php?" + urllib.parse.urlencode(dict(db, qt="0123456789abcdef")))
    if "no longer remembered" not in page or 'name="query"' in page:
        failures.append("dataexport.php with an unknown qt -> expected 'no longer remembered', no form")

    # Query results paged with qt tokens: two "tabs" with their own query
    def run_query(sql):
        status, body = fetch(base + "sql.php", dict(db, query=sql, paginate="on", page_size="25"))
        check("POST sql.php paginate " + sql, status, body)
        m = re.search(r'href="(display\.php\?[^"]*qt=[0-9a-f]{16}[^"]*page=2)"', body)
        if not m:
            failures.append("POST sql.php paginate %s -> no page 2 link with a qt token" % sql)
            return None
        return base + html.unescape(m.group(1))

    # With the grid ticked, a statement that returns no rows runs as typed
    # (the grid would wrap it in SELECT * FROM (...)); queries still page.
    for sql, expect in (("create SCHEMA grid_ddl_test;", "sql-ok"),
                        ("drop schema grid_ddl_test", "sql-ok"),
                        ("-- note\n(select g from generate_series(1, 100) g)", "qt=")):
        status, body = fetch(base + "sql.php", dict(db, query=sql, paginate="on", page_size="25"))
        check("POST sql.php paginate " + sql, status, body)
        if expect not in body or "syntax error" in body:
            failures.append("POST sql.php paginate %r -> expected %r, got %s"
                            % (sql, expect, re.sub(r"\s+", " ", body)[-400:]))

    page2_a = run_query("SELECT id, val FROM public.plain ORDER BY id")
    page2_b = run_query("SELECT g AS tab_b FROM generate_series(1000, 1100) g")
    for url, expect, reject in ((page2_a, md5(26), "tab_b"), (page2_b, "1025", md5(26))):
        if url is None:
            continue
        status, body = fetch(url)
        check(url, status, body)
        # The recent queries menu lists the other query too: not a result row
        body = re.sub(r'data-history="[^"]*"', '', body)
        if expect not in body or reject in body or "Rows 26–50" not in html.unescape(body):
            failures.append("%s -> page 2 shows the wrong query's rows" % url)
    if page2_a:
        status, body = fetch(page2_a + "&count=exact")
        if "Rows 26–50 of 100" not in html.unescape(body):
            failures.append("%s&count=exact -> expected 'Rows 26–50 of 100'" % page2_a)

    # sql.php without a query (reload, back button) goes to the SQL editor
    status, body = fetch(base + "sql.php?" + urllib.parse.urlencode(db))
    check("GET sql.php", status, body)
    if "could not find the query" in body or 'name="query"' not in body:
        failures.append("GET sql.php -> expected the SQL editor")


if __name__ == "__main__":
    if len(sys.argv) != 5:
        sys.exit(__doc__)
    sys.exit(main(*sys.argv[1:]))

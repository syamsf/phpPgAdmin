#!/usr/bin/env python3
"""
Security regression tests: plant an attack against a running phpPgAdmin
and check that it does not work.

Each test gets a fresh, logged-in Client (as a superuser, the victim) and
creates whatever malicious objects it needs, cleaning up after itself.

    python3 tests/security.py http://127.0.0.1:8080 db:5432:allow ppa ppa
"""

import hashlib
import html
import re
import sys
import traceback
import urllib.error
import urllib.parse
import urllib.request
from http.cookiejar import CookieJar

DB = "ppa_test"
TESTS = []

META_TOKEN = re.compile(r'<meta name="ppa-csrf" content="([^"]+)"')
HIDDEN = re.compile(r'<input type="hidden" name="([^"]+)" value="([^"]*)"')
FIRST_CELL = re.compile(r'<table class="data-grid">.*?<tbody>\s*<tr[^>]*>\s*<td>(.*?)</td>', re.S)


def test(fn):
    TESTS.append(fn)
    return fn


class Failure(Exception):
    pass


def check(cond, msg):
    if not cond:
        raise Failure(msg)


class Client:
    """A browser stand-in: keeps cookies, sends the page's CSRF token."""

    def __init__(self, base, server):
        self.base = base.rstrip("/") + "/"
        self.server = server
        self.token = None
        self.status = None
        self.headers = {}
        self.opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(CookieJar()))

    def _open(self, url, body=None, headers=None):
        req = urllib.request.Request(url, body, headers or {})
        try:
            with self.opener.open(req, timeout=60) as resp:
                self.status, self.headers = resp.status, dict(resp.headers)
                page = resp.read().decode("utf-8", "replace")
        except urllib.error.HTTPError as e:
            self.status, self.headers = e.code, dict(e.headers)
            page = e.read().decode("utf-8", "replace")
        m = META_TOKEN.search(page)
        if m:
            self.token = html.unescape(m.group(1))
        return self.status, page

    def url(self, path, **params):
        q = urllib.parse.urlencode(params, doseq=True)
        return self.base + path + ("?" + q if q else "")

    def get(self, path, **params):
        return self._open(self.url(path, **params))

    def post(self, path, data, token=True):
        data = dict(data)
        if token and self.token and "ppa_csrf" not in data:
            data["ppa_csrf"] = self.token
        body = urllib.parse.urlencode(data, doseq=True).encode()
        return self._open(self.base + path, body)

    def login_fields(self, user, password):
        return {
            "loginServer": self.server,
            "loginUsername": user,
            "loginPassword_" + hashlib.md5(self.server.encode()).hexdigest(): password,
            "loginSubmit": "Login",
        }

    def login(self, user, password, extra=None):
        # Like a browser: open the login page first (for its token), then post it.
        self.get("redirect.php", subject="server", server=self.server)
        data = {"subject": "server", "server": self.server}
        data.update(extra or {})
        data.update(self.login_fields(user, password))
        return self.post("redirect.php", data)

    def sql(self, query, database=DB):
        """Runs SQL through the SQL editor (sql.php) and returns the page."""
        if self.token is None:
            self.get("database.php", server=self.server, database=database, subject="database", action="sql")
        status, page = self.post("sql.php", {"server": self.server, "database": database, "query": query})
        return page

    def scalar(self, query, database=DB):
        """First cell of a query's result, as text."""
        page = self.sql(query, database)
        m = FIRST_CELL.search(page)
        check(m, "no result for: %s\n%s" % (query, re.sub(r"\s+", " ", page)[-600:]))
        return html.unescape(re.sub(r"<[^>]+>", "", m.group(1))).strip()


# --- H1: the login page must not carry an action into the page after login

@test
def test_login_does_not_run_carried_action(c):
    c.sql("CREATE DATABASE ppa_sec_victim", database="postgres")
    try:
        victim = Client(c.base, c.server)
        status, page = victim.get("all_db.php", server=c.server, subject="server",
                                  action="drop", drop="1", dropdatabase="ppa_sec_victim")
        check("loginUsername" in page, "expected the login page for a new session")
        fields = dict(HIDDEN.findall(page))
        fields.update(victim.login_fields(USER, PASSWORD))
        victim.post("redirect.php", fields)
        n = c.scalar("SELECT count(*) FROM pg_database WHERE datname = 'ppa_sec_victim'", database="postgres")
        check(n == "1", "database was dropped by the action carried through login")
    finally:
        c.sql("DROP DATABASE IF EXISTS ppa_sec_victim", database="postgres")


# --- M4/L2: POSTs need the page's token; state changes need POST

def table_exists(c, name):
    return c.scalar("SELECT count(*) FROM pg_class WHERE relname = '%s'" % name) == "1"


@test
def test_post_without_token_rejected(c):
    c.sql("DROP TABLE IF EXISTS ppa_sec_csrf")
    status, page = c.post("sql.php", {"server": c.server, "database": DB,
                                      "query": "CREATE TABLE ppa_sec_csrf (i int)"}, token=False)
    check(status == 403, "POST without token answered HTTP %s, expected 403" % status)
    check(not table_exists(c, "ppa_sec_csrf"), "the SQL ran without a token")


@test
def test_csrf_failure_page_renders(c):
    status, page = c.post("sql.php", {"server": c.server, "database": DB, "query": "SELECT 1"}, token=False)
    check(status == 403, "expected HTTP 403, got %s" % status)
    check("Fatal error" not in page and "</html>" in page, "the 403 page is blank or fatal: %r" % page[-200:])
    check("This form has expired" in page, "the 403 page lacks the expired-form message")


@test
def test_post_with_token_works(c):
    c.sql("DROP TABLE IF EXISTS ppa_sec_csrf")
    c.sql("CREATE TABLE ppa_sec_csrf (i int)")
    check(table_exists(c, "ppa_sec_csrf"), "the SQL editor no longer runs SQL")
    c.sql("DROP TABLE ppa_sec_csrf")


@test
def test_get_does_not_drop_database(c):
    c.sql("CREATE DATABASE ppa_sec_victim", database="postgres")
    try:
        c.get("all_db.php", server=c.server, subject="server", action="drop", drop="1",
              **{"dropdatabase[]": "ppa_sec_victim"})
        n = c.scalar("SELECT count(*) FROM pg_database WHERE datname = 'ppa_sec_victim'", database="postgres")
        check(n == "1", "a GET dropped the database")
    finally:
        c.sql("DROP DATABASE IF EXISTS ppa_sec_victim", database="postgres")


@test
def test_get_does_not_run_history(c):
    c.sql("CREATE TABLE ppa_sec_hist (i int)")
    c.sql("DROP TABLE ppa_sec_hist")
    status, page = c.get("history.php", server=c.server, database=DB)
    ids = re.findall(r'queryid=([0-9.]+)', html.unescape(page))
    check(ids, "no history entries listed")
    # The newest entries are the DROP, then the CREATE; try every id.
    for qid in ids:
        c.get("sql.php", server=c.server, database=DB, subject="history", queryid=qid)
    check(not table_exists(c, "ppa_sec_hist"), "a GET of sql.php re-ran a history query")


# --- H3: a type's name must not choose how its values are shown

@test
def test_type_named_verbatim_is_escaped(c):
    c.sql("DROP TABLE IF EXISTS public.sec_vt")
    c.sql("DROP TYPE IF EXISTS public.verbatim")
    try:
        c.sql("CREATE TYPE public.verbatim AS (v text)")
        c.sql("CREATE TABLE public.sec_vt (id int PRIMARY KEY, c public.verbatim)")
        c.sql("INSERT INTO public.sec_vt VALUES (1, ROW('<b id=xss>'))")
        status, page = c.get("display.php", server=c.server, database=DB, schema="public",
                             subject="table", table="sec_vt")
        check("<b id=xss>" not in page, "browse page printed the value unescaped")
        check("&lt;b id=xss&gt;" in page, "browse page lacks the escaped value")
        page = c.sql("SELECT * FROM public.sec_vt")
        check("<b id=xss>" not in page, "SQL result printed the value unescaped")
        check("&lt;b id=xss&gt;" in page, "SQL result lacks the escaped value")
    finally:
        c.sql("DROP TABLE IF EXISTS public.sec_vt")
        c.sql("DROP TYPE IF EXISTS public.verbatim")


@test
def test_macaddr_still_renders(c):
    check(c.scalar("SELECT '08:00:2b:01:02:03'::macaddr") == "08:00:2b:01:02:03", "macaddr value not shown")


# --- H6/H7/H8: names reach inline scripts only through one JSON helper

def script_bodies(page):
    return re.findall(r"<script[^>]*>(.*?)</script>", page, re.S)


@test
def test_db_name_in_processes_js(c):
    name = 'sec"x\';</script><b id=xss>'
    quoted = name.replace('"', '""')
    c.sql('CREATE DATABASE "%s"' % quoted, database="postgres")
    try:
        status, page = c.get("database.php", server=c.server, database=name,
                             subject="database", action="processes")
        check("<b id=xss>" not in page, "database name broke out of the inline script")
        m = re.search(r"var Database = \{.*?\n\};", page, re.S)
        check(m, "no Database script on the page")
        check("</script" not in m.group(0).lower(), "raw </script> inside var Database")
        check("dbname:'" not in m.group(0), "dbname still written as a hand-quoted string")
    finally:
        c.sql('DROP DATABASE IF EXISTS "%s"' % quoted, database="postgres")


@test
def test_type_name_in_create_function(c):
    names = ["\\x3cb id=xss\\x3e", "</script><b id=xss>"]
    for n in names:
        c.sql('DROP TABLE IF EXISTS public."%s"' % n)
    try:
        for n in names:
            c.sql('CREATE TABLE public."%s" ()' % n)
        status, page = c.get("functions.php", server=c.server, database=DB, schema="public",
                             subject="schema", action="create")
        check("<b id=xss>" not in page, "type name printed as markup")
        js = "\n".join(script_bodies(page))
        check("\\x3cb" not in js.replace("\\\\x3cb", ""), "type name decodes to markup inside a JS string")
        check("g_types_select" not in page, "types still passed as an HTML string")
    finally:
        for n in names:
            c.sql('DROP TABLE IF EXISTS public."%s"' % n)


def fk_tables(c, pcols, ccols, fk):
    c.sql("DROP TABLE IF EXISTS public.sec_c")
    c.sql("DROP TABLE IF EXISTS public.sec_p")
    c.sql("CREATE TABLE public.sec_p (%s)" % pcols)
    c.sql("CREATE TABLE public.sec_c (%s, %s)" % (ccols, fk))


@test
def test_fk_column_backslash(c):
    try:
        fk_tables(c, "x text PRIMARY KEY, y text", '"a\\" text, "+alert(1)]};{//" text',
                  'FOREIGN KEY ("a\\") REFERENCES public.sec_p (x)')
        status, page = c.get("tables.php", server=c.server, database=DB, schema="public",
                             subject="table", table="sec_c", action="confinsertrow")
        check("var constrs" in page, "page has no FK script (setup broken)")
        check("'a\\'" not in page, "column name ending in a backslash escapes its closing quote")
    finally:
        c.sql("DROP TABLE IF EXISTS public.sec_c")
        c.sql("DROP TABLE IF EXISTS public.sec_p")


@test
def test_fk_parent_name_in_ajax(c):
    try:
        fk_tables(c, '"<b id=xss>" text PRIMARY KEY', "a text",
                  'FOREIGN KEY (a) REFERENCES public.sec_p ("<b id=xss>")')
        c.get("tables.php", server=c.server, database=DB, schema="public",
              subject="table", table="sec_c", action="confinsertrow")
        status, page = c.post("ajax-ac-insert.php?server=" + urllib.parse.quote(c.server),
                              {"fattpos": "0", "fvalue": "", "database": DB, "keys[]": "1",
                               "keynames[]": "a", "fkeynames[]": "<b id=xss>",
                               "f_table": "sec_p", "f_schema": "public", "offset": "0"})
        check(status == 200, "ajax request failed: HTTP %s" % status)
        check("<b id=xss>" not in page, "parent column name echoed as markup")
    finally:
        c.sql("DROP TABLE IF EXISTS public.sec_c")
        c.sql("DROP TABLE IF EXISTS public.sec_p")


# --- H4/H5/M2/L4: names and request values are escaped in HTML

def raw_markup(page, n):
    return "<b id=xss%d" % n in page


def sec_fixture(c):
    c.sql("DROP SCHEMA IF EXISTS sec CASCADE")
    c.sql('DROP ROLE IF EXISTS "x""><b id=xss4>"')
    c.sql("CREATE SCHEMA sec")
    c.sql('CREATE TABLE sec."<b id=xss1>" ("""><b id=xss2>" text PRIMARY KEY, "<b id=xss8>" text)')
    c.sql('INSERT INTO sec."<b id=xss1>" VALUES (\'v\')')
    c.sql("CREATE TYPE sec.mood AS ENUM ('<b id=xss3>')")
    c.sql('CREATE VIEW sec."<b id=xss1v>" AS SELECT * FROM sec."<b id=xss1>"')
    c.sql("CREATE FUNCTION sec.trgf() RETURNS trigger LANGUAGE plpgsql AS 'BEGIN RETURN NEW; END'")
    c.sql('CREATE TRIGGER "<b id=xss1t>" BEFORE INSERT ON sec."<b id=xss1>" FOR EACH ROW EXECUTE PROCEDURE sec.trgf()')
    c.sql('CREATE ROLE "x""><b id=xss4>" LOGIN')


def sec_cleanup(c):
    c.sql("DROP SCHEMA IF EXISTS sec CASCADE")
    c.sql('DROP ROLE IF EXISTS "x""><b id=xss4>"')


@test
def test_names_escaped_in_html(c):
    try:
        sec_fixture(c)
        common = dict(server=c.server, database=DB, schema="sec")
        ekey = {'key["><b id=xss2>]': "v", "page": "1", "sortkey": "", "sortdir": "", "strings": "collapsed"}
        pages = [
            ("browse", c.get("display.php", subject="table", table="<b id=xss1>", **common)),
            ("confeditrow", c.get("display.php", subject="table", table="<b id=xss1>", action="confeditrow",
                                  **ekey, **common)),
            ("tables selectrows", c.get("tables.php", subject="table", table="<b id=xss1>", action="confselectrows", **common)),
            ("views selectrows", c.get("views.php", subject="view", view="<b id=xss1v>", action="confselectrows", **common)),
            ("type properties", c.get("types.php", action="properties", type="mood", **common)),
            ("groups create", c.get("groups.php", action="create", **common)),
            ("triggers", c.get("triggers.php", subject="table", table="<b id=xss1>", **common)),
            ("tables list", c.get("tables.php", subject="schema", **common)),
            ("history confdel", c.get("history.php", action="confdelhistory", queryid='"><b id=xss5>', **common)),
            ("fulltext dropmapping", c.get("fulltext.php", action="dropmapping", mapping="x", ftscfg='"><b id=xss6>', **common)),
            ("plugin", c.get("plugin.php", plugin="<b id=xss7>", action="x", server=c.server)),
            ("roles list", c.get("roles.php", subject="server", server=c.server)),
        ]
        wanted = {"browse": (1, 2), "confeditrow": (2, 8), "tables selectrows": (2,), "views selectrows": (2,),
                  "type properties": (3,), "groups create": (4,), "triggers": (1,), "tables list": (1,),
                  "history confdel": (5,), "fulltext dropmapping": (6,), "plugin": (7,), "roles list": (4,)}
        bad = []
        for name, (status, page) in pages:
            for n in range(1, 9):
                if raw_markup(page, n):
                    bad.append("%s: xss%d" % (name, n))
        check(not bad, "raw markup echoed: " + ", ".join(bad))
        # fixture sanity: the escaped form must be present where expected
        for name, (status, page) in pages:
            for n in wanted[name]:
                check("&lt;b id=xss%d" % n in page, "%s: escaped xss%d missing (page not rendered?)" % (name, n))
    finally:
        sec_cleanup(c)


@test
def test_printtable_links_still_work(c):
    try:
        sec_fixture(c)
        common = dict(server=c.server, database=DB, schema="sec")
        status, page = c.get("triggers.php", subject="table", table="<b id=xss1>", **common)
        hrefs = [html.unescape(h) for h in re.findall(r'<a href="([^"]*functions\.php[^"]*)"', page)]
        check(hrefs, "no function link in the triggers list")
        q = urllib.parse.parse_qs(urllib.parse.urlparse(hrefs[0]).query)
        check(q.get("action") == ["properties"] and q.get("server") == [c.server] and q.get("database") == [DB]
              and q.get("function"), "bad function link: %s" % hrefs[0])
        status, page = c.get("tables.php", subject="schema", **common)
        links = [html.unescape(h) for h in re.findall(r'<a href="(redirect\.php[^"]*subject=table[^"]*)"', page)]
        check(links, "no table link in the tables list")
        q = urllib.parse.parse_qs(urllib.parse.urlparse(links[0]).query)
        check(q.get("subject") == ["table"] and q.get("table") == ["<b id=xss1>"] and q.get("schema") == ["sec"],
              "bad table link: %s" % links[0])
    finally:
        sec_cleanup(c)


@test
def test_edit_row_roundtrip_with_quote_and_backslash(c):
    try:
        c.sql("DROP TABLE IF EXISTS public.\"O'Reilly\"")
        c.sql("CREATE TABLE public.\"O'Reilly\" (id int PRIMARY KEY, \"a\\b\" text)")
        c.sql("INSERT INTO public.\"O'Reilly\" VALUES (1, 'old')")
        status, page = c.get("display.php", server=c.server, database=DB, schema="public", subject="table",
                             table="O'Reilly", action="confeditrow",
                             page="1", sortkey="", sortdir="", strings="collapsed", **{"key[id]": "1"})
        form = page[page.index('<form'):]
        fields = {html.unescape(n): html.unescape(v) for n, v in HIDDEN.findall(form)}
        fields["values[a\\b]"] = "new"
        fields["format[a\\b]"] = "VALUE"
        fields["format[id]"] = "VALUE"
        fields["values[id]"] = "1"
        fields["action"] = "editrow"
        fields["save"] = "1"
        c.post("display.php", fields)
        v = c.scalar("SELECT \"a\\b\" FROM public.\"O'Reilly\" WHERE id = 1")
        check(v == "new", "edited value not saved, got %r" % v)
    finally:
        c.sql("DROP TABLE IF EXISTS public.\"O'Reilly\"")


@test
def test_fts_name_with_quote_is_escaped(c):
    name = "it's_cfg"
    try:
        c.sql('DROP TEXT SEARCH CONFIGURATION IF EXISTS public."%s"' % name)
        c.sql('CREATE TEXT SEARCH CONFIGURATION public."%s" (COPY = english)' % name)
        status, page = c.get("fulltext.php", server=c.server, database="ppa_test", schema="public",
                              subject="schema", action="viewconfig", ftscfg=name)
        check("SQL error" not in page and "Fatal error" not in page,
              "name with a quote broke the query: %s" % re.sub(r"\s+", " ", page)[-400:])
        check("asciiword" in page, "mapping list missing from the page")
    finally:
        c.sql('DROP TEXT SEARCH CONFIGURATION IF EXISTS public."%s"' % name)


@test
def test_fts_mapping_name_cannot_inject(c):
    cfg = "sec_cfg_map"
    c.sql("DROP TABLE IF EXISTS public.sec_marker_map")
    try:
        c.sql('DROP TEXT SEARCH CONFIGURATION IF EXISTS public."%s"' % cfg)
        c.sql('CREATE TEXT SEARCH CONFIGURATION public."%s" (COPY = english)' % cfg)
        f = {"action": "altermapping", "alter": "1", "server": c.server, "database": "ppa_test",
             "schema": "public", "subject": "schema", "ftscfg": cfg, "formDictionary": "simple"}
        c.post("fulltext.php", dict(f, formMapping='asciiword" WITH simple; CREATE TABLE public.sec_marker_map (i int); --'))
        check(c.scalar("SELECT (to_regclass('public.sec_marker_map') IS NULL)::text") == "true",
              "extra statement in formMapping was executed")
        c.post("fulltext.php", dict(f, formDictionary='simple"; CREATE TABLE public.sec_marker_map (i int); --',
                                    formMapping="asciiword"))
        check(c.scalar("SELECT (to_regclass('public.sec_marker_map') IS NULL)::text") == "true",
              "extra statement in formDictionary was executed")
        # a valid change still works
        c.post("fulltext.php", dict(f, formMapping="asciiword"))
        check(c.scalar("SELECT d.dictname FROM pg_ts_config_map m JOIN pg_ts_config c ON c.oid = m.mapcfg "
                       "JOIN pg_ts_dict d ON d.oid = m.mapdict WHERE c.cfgname = '%s' "
                       "AND m.maptokentype = 1" % cfg) == "simple", "valid mapping change did not work")
    finally:
        c.sql("DROP TABLE IF EXISTS public.sec_marker_map")
        c.sql('DROP TEXT SEARCH CONFIGURATION IF EXISTS public."%s"' % cfg)


@test
def test_ac_insert_quote_in_value(c):
    c.sql("DROP TABLE IF EXISTS public.sec_ac")
    try:
        c.sql("CREATE TABLE public.sec_ac (id text PRIMARY KEY)")
        c.sql("INSERT INTO public.sec_ac VALUES ('O''Neil'), ('Other')")
        base = {"server": c.server, "database": "ppa_test", "f_schema": "public",
                "f_table": "sec_ac", "fkeynames[]": "id", "keys[]": "id", "fattpos": "0"}
        _, page = c.post("ajax-ac-insert.php", dict(base, fvalue="O'N", offset="0"))
        check("Neil" in page and "SQL error" not in page,
              "quote in fvalue broke the query: %s" % page[:300])
        _, page = c.post("ajax-ac-insert.php", dict(base, fvalue="", offset="0 UNION SELECT 'zzinj'"))
        check("zzinj" not in page and "SQL error" not in page, "offset was not treated as an integer")
        # LIKE wildcards in the value are literal, not pattern metacharacters
        _, page = c.post("ajax-ac-insert.php", dict(base, fvalue="%", offset="0"))
        check("Neil" not in page and "SQL error" not in page, "wildcard in fvalue matched rows or errored")
        _, page = c.post("ajax-ac-insert.php", dict(base, fvalue="\\", offset="0"))
        check("SQL error" not in page, "backslash in fvalue errored")
        # same with standard_conforming_strings off (a per-database setting)
        c.sql("ALTER DATABASE ppa_test SET standard_conforming_strings = off", database="postgres")
        try:
            c2 = Client(c.base, c.server)
            c2.login(USER, PASSWORD)
            c2.sql("SELECT 1")
            for v, want in (("O'N", True), ("%", False), ("\\", False)):
                _, page = c2.post("ajax-ac-insert.php", dict(base, fvalue=v, offset="0"))
                check("SQL error" not in page, "fvalue %r errored with standard_conforming_strings off: %s" % (v, page[:300]))
                check(("Neil" in page) == want, "fvalue %r matched wrongly with standard_conforming_strings off" % v)
        finally:
            c.sql("ALTER DATABASE ppa_test RESET standard_conforming_strings", database="postgres")
    finally:
        c.sql("DROP TABLE IF EXISTS public.sec_ac")


@test
def test_sequence_numbers_validated(c):
    c.sql("DROP SEQUENCE IF EXISTS public.sec_seq")
    c.sql("DROP TABLE IF EXISTS public.sec_marker_seq")
    try:
        c.post("sequences.php", {"action": "save_create_sequence", "create": "1", "server": c.server,
               "database": "ppa_test", "schema": "public", "formSequenceName": "sec_seq",
               "formIncrement": "1; CREATE TABLE sec_marker_seq (i int)", "formMinValue": "",
               "formMaxValue": "", "formStartValue": "", "formCacheValue": ""})
        check(c.scalar("SELECT to_regclass('public.sec_marker_seq') IS NULL")
              in ("t", "TRUE", "true"),
              "extra statement in formIncrement was executed")
        c.post("sequences.php", {"action": "save_create_sequence", "create": "1", "server": c.server,
               "database": "ppa_test", "schema": "public", "formSequenceName": "sec_seq",
               "formIncrement": "2", "formMinValue": "", "formMaxValue": "", "formStartValue": "",
               "formCacheValue": ""})
        # nextval twice and compare: works on every version (pg_sequences is 10+)
        first = int(c.scalar("SELECT nextval('public.sec_seq')"))
        second = int(c.scalar("SELECT nextval('public.sec_seq')"))
        check(second - first == 2, "valid create did not work (increment %d)" % (second - first))
    finally:
        c.sql("DROP SEQUENCE IF EXISTS public.sec_seq")
        c.sql("DROP TABLE IF EXISTS public.sec_marker_seq")


@test
def test_trigger_options_validated(c):
    c.sql("DROP TABLE IF EXISTS public.sec_trg")
    c.sql("DROP TABLE IF EXISTS public.sec_marker_trg")
    try:
        c.sql("CREATE TABLE public.sec_trg (id int)")
        c.sql("CREATE OR REPLACE FUNCTION public.sec_trgf() RETURNS trigger LANGUAGE plpgsql AS 'BEGIN RETURN NEW; END'")
        f = {"action": "save_create", "server": c.server, "database": "ppa_test", "schema": "public",
             "table": "sec_trg", "formTriggerName": "sec_t", "formFunction": "sec_trgf",
             "formExecTime": "BEFORE", "formEvent": "INSERT", "formFrequency": "ROW",
             "formTriggerArgs": ""}
        c.post("triggers.php", dict(f, formFrequency="ROW EXECUTE PROCEDURE sec_trgf(); CREATE TABLE sec_marker_trg (i int); --"))
        check(c.scalar("SELECT to_regclass('public.sec_marker_trg') IS NULL")
              in ("t", "TRUE", "true"),
              "extra statement in formFrequency was executed")
        c.post("triggers.php", dict(f, formTriggerArgs="'a'); CREATE TABLE sec_marker_trg (i int); --"))
        check(c.scalar("SELECT to_regclass('public.sec_marker_trg') IS NULL")
              in ("t", "TRUE", "true"),
              "extra statement in formTriggerArgs was executed")
        for bad in ("'a', b); CREATE TABLE sec_marker_trg (i int); --", "'unterminated", "a b", "\"Q\"",
                    "'a' 'b'", "1; CREATE TABLE sec_marker_trg (i int)"):
            c.sql("DROP TRIGGER IF EXISTS sec_t ON public.sec_trg")
            c.post("triggers.php", dict(f, formTriggerArgs=bad))
            check(c.scalar("SELECT to_regclass('public.sec_marker_trg') IS NULL")
                  in ("t", "TRUE", "true"), "bad args %r executed" % bad)
            check(c.scalar("SELECT count(*) FROM pg_trigger WHERE tgname='sec_t'") == "0",
                  "bad args %r created a trigger" % bad)
        for given, want in (("'a,b', 'c'", "('a,b', 'c')"), ("'foo'", "('foo')"), ("'it''s'", "('it''s')"),
                            ("42", "('42')"), ("Foo, 'x'", "('foo', 'x')"), ("", "()")):
            c.sql("DROP TRIGGER IF EXISTS sec_t ON public.sec_trg")
            c.post("triggers.php", dict(f, formTriggerArgs=given))
            args = c.scalar("SELECT split_part(pg_get_triggerdef(oid), 'sec_trgf', 2) FROM pg_trigger "
                            "WHERE tgname='sec_t'").replace("\n", "")
            check(args == want, "args %r gave %r, wanted %r" % (given, args, want))
    finally:
        c.sql("DROP TABLE IF EXISTS public.sec_trg")
        c.sql("DROP TABLE IF EXISTS public.sec_marker_trg")
        c.sql("DROP FUNCTION IF EXISTS public.sec_trgf()")


# --- M1, M3, L3: connection security and exports

@test
def test_sslmode_reaches_libpq(c):
    """The server "Tls" (db:5432?sslmode=require in tests/compose.yaml's
    PPA_SERVERS, which docker/config.inc.php turns into a per-server sslmode)
    points at the test database, which has no SSL. If sslmode really reaches
    libpq, the login fails with the SSL reason. (Before, only host and port
    got through, and the login worked in clear text.)"""
    t = Client(c.base, "db:5432:require")
    status, page = t.login(USER, PASSWORD)
    check("loginUsername" in page, "login to the sslmode=require server worked without SSL")
    check("The SSL settings of the server and of phpPgAdmin don't match."
          in html.unescape(page), "no SSL reason on the login page: " + re.sub(r"\s+", " ", page)[-400:])


@test
def test_dbexport_unknown_output_is_plain(c):
    status, page = c.get("dbexport.php", server=c.server, database=DB, subject="database",
                         what="structureonly", output="x", s_format="sql")
    ctype = c.headers.get("Content-Type", "")
    check(ctype.startswith("text/plain"), "Content-Type was %r" % ctype)


@test
def test_scoped_export_stays_in_db(c):
    """The role "scoped" can only connect to ppa_other (see fixtures.sql)."""
    o = Client(c.base, "db:5432:allow:ppa_other")
    status, page = o.login("scoped", "scoped")
    check("loginUsername" not in page, "scoped login to ppa_other failed")
    status, dump = o.get("dbexport.php", server=o.server, subject="database", what="structureonly",
                         output="show", s_format="sql")
    check("PostgreSQL database dump" in dump, "no dump of ppa_other: " + dump[:300])
    check("shop.orders" not in dump, "dump contains ppa_test objects")
    # Asking for another database must not dump that one.
    status, dump = o.get("dbexport.php", server=o.server, database="ppa_test", subject="database",
                         what="structureonly", output="show", s_format="sql")
    check("shop.orders" not in dump, "dump of the requested ppa_test, outside the login")

@test
def test_login_password_is_literal(c):
    """Text in the password or database name is treated literally: it never
    changes the host, user or sslmode of the connection."""
    for pw in ("@db:5432/", "x@db:5432/postgres", "a'b\\c @db:5432/ sslmode=disable"):
        t = Client(c.base, "db:5432:require")
        status, page = t.login(USER, pw)
        text = html.unescape(page)
        check("loginUsername" in page, "login on the sslmode=require server worked with password %r" % pw)
        check("The SSL settings of the server and of phpPgAdmin don't match." in text,
              "no SSL reason for password %r" % pw)
        a = Client(c.base, c.server)
        status, page = a.login(USER, pw)
        check("loginUsername" in page, "login worked with password %r" % pw)
        check("The password is wrong" in html.unescape(page) or "password" in html.unescape(page).lower(),
              "no password reason for %r" % pw)
    # The same for the database name of a request.
    for db in ("x@db:5432/", "x@db:5432/ppa_test"):
        status, page = c.get("database.php", server=c.server, database=db, subject="database")
        check("shop" not in page and "CREATE TABLE" not in page, "database=%r gave a working page" % db)
        check("does not exist" in page or "failed" in page.lower() or "loginUsername" in page,
              "database=%r did not fail normally: %s" % (db, re.sub(r"\s+", " ", page)[:300]))


@test
def test_invalid_sslmode_is_rejected(c):
    """Unit check of the sslmode allow-list in classes/database/Connection.php,
    run by the php of the app container (no local php needed), including the
    class file the way the app does."""
    import subprocess, os
    here = os.path.dirname(os.path.abspath(__file__))
    code = ("define('ADODB_FETCH_ASSOC',2); "
            "$_SERVER['SCRIPT_FILENAME']='/var/www/html/x.php'; "
            "foreach (array('disable','allow','prefer','require','verify-ca','verify-full','unspecified','') as $m) "
            "if (!Connection::validSslmode($m)) exit(1); "
            "foreach (array('legacy','Require','require ','x host=evil') as $m) "
            "if (Connection::validSslmode($m)) exit(2); "
            "if (strpos(Connection::conninfo('h',1,'unspecified','u','p','d'),'sslmode')!==false) exit(3); "
            "foreach (array('unspecified','',null,'legacy') as $m) if (Connection::sslmodeForLibpq($m)!==null) exit(4); "
            "if (Connection::sslmodeForLibpq('verify-full')!=='verify-full') exit(5);")
    r = subprocess.run(["docker", "compose", "-f", "compose.yaml", "exec", "-T", "-w", "/var/www/html", "app", "php", "-r",
                        "chdir('/var/www/html'); include_once('./classes/database/Connection.php'); " + code],
                       capture_output=True, text=True, cwd=here)
    check(r.returncode == 0, "allow-list check exited %s %s %s" % (r.returncode, r.stdout[:200], r.stderr[:200]))


@test
def test_csrf_token_renewed_at_login(c):
    t = Client(c.base, c.server)
    t.get("redirect.php", subject="server", server=c.server)
    before = t.token
    check(before, "no token on the login page")
    status, page = t.login(USER, PASSWORD)
    check("loginUsername" not in page, "login failed")
    check(t.token and t.token != before, "token after login is the one from the login page")


@test
def test_csrf_header_or_field_accepted(c):
    """Either the field or the X-PPA-CSRF header may carry the token."""
    c.get("database.php", server=c.server, database=DB, subject="database", action="sql")
    body = urllib.parse.urlencode({"server": c.server, "database": DB, "query": "select 1",
                                   "ppa_csrf": "wrong"}).encode()
    status, page = c._open(c.base + "sql.php", body, {"X-PPA-CSRF": c.token})
    check(status == 200, "valid header with a wrong field gave %s" % status)
    status, page = c._open(c.base + "sql.php", body, {"X-PPA-CSRF": "wrong"})
    check(status == 403, "wrong header and field gave %s" % status)


@test
def test_login_error_hides_detail(c):
    """Before login, only the plain-language reason is shown, never the raw
    libpq message (host, port and addresses of the database server)."""
    t = Client(c.base, c.server)
    status, page = t.login(USER, "definitely-wrong-password")
    text = html.unescape(page)
    check("The username or password is wrong." in text, "no plain reason: " + re.sub(r"\s+", " ", text)[-400:])
    for raw in ("connection to server at", "login-error-detail", "pg_connect", "FATAL"):
        check(raw not in text, "login page shows %r" % raw)


@test
def test_intro_hides_php_version(c):
    status, page = c.get("intro.php")
    check(status == 200 and "phpPgAdmin" in page, "intro.php did not load (HTTP %s)" % status)
    check(not re.search(r"PHP\s*\(?\s*\d+\.\d+", page) and "(PHP " not in page,
          "intro.php shows the PHP version")


def main(base, server, user, password):
    global USER, PASSWORD
    USER, PASSWORD = user, password
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
    print("%d failures" % failures)
    return 1 if failures else 0


if __name__ == "__main__":
    if len(sys.argv) < 5:
        sys.exit(__doc__)
    sys.exit(main(*sys.argv[1:5]))

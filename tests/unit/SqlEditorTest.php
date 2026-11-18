<?php

require_once './classes/SqlEditor.php';

// --- statementHeads: unchanged behaviour (it now shares the lexer)

function test_statement_heads_basic() {
	assert_same(array('SELECT'), SqlEditor::statementHeads('select 1'));
	assert_same(array('CREATE TABLE T', 'INSERT INTO T'),
		SqlEditor::statementHeads("create table t (a int); insert into t values (1);"));
	assert_same(array('ALTER TABLE X'), SqlEditor::statementHeads("-- c\n/* a /* nested */ b */ alter table x add b int"));
}

function test_statement_heads_skips_quotes() {
	assert_same(array('SELECT AS S'), SqlEditor::statementHeads("select 'a; drop table x' as s"));
	assert_same(array('SELECT', 'DROP TABLE Y'), SqlEditor::statementHeads("select \"x;y\"; drop table y"));
	assert_same(array('CREATE FUNCTION F'),
		SqlEditor::statementHeads("create function f() returns int as \$body\$ select 1; \$body\$ language sql"));
	assert_same(array('SELECT E'), SqlEditor::statementHeads("select E'it\\'s; ok'"));
	assert_same(array('SELECT', 'SELECT'), SqlEditor::statementHeads("select (1;2); select 3"));
}

// --- unsafeStatements: DELETE without WHERE and TRUNCATE

function test_unsafe_delete_without_where() {
	assert_same(array('DELETE FROM t'), SqlEditor::unsafeStatements('DELETE FROM t'));
	assert_same(array('delete from shop.orders'), SqlEditor::unsafeStatements("  delete\n from   shop.orders ;  "));
	assert_same(array('DELETE FROM ONLY t USING u'), SqlEditor::unsafeStatements('DELETE FROM ONLY t USING u'));
}

function test_delete_with_where_is_fine() {
	assert_same(array(), SqlEditor::unsafeStatements('DELETE FROM t WHERE id = 1'));
	assert_same(array(), SqlEditor::unsafeStatements('DELETE FROM t USING u WHERE t.id = u.id'));
	assert_same(array(), SqlEditor::unsafeStatements('DELETE FROM t WHERE CURRENT OF c'));
	assert_same(array(), SqlEditor::unsafeStatements('delete from t where true returning *'));
}

function test_where_only_in_a_subquery_does_not_count() {
	assert_same(array('DELETE FROM t USING (SELECT id FROM u WHERE x) s'),
		SqlEditor::unsafeStatements('DELETE FROM t USING (SELECT id FROM u WHERE x) s'));
}

function test_delete_in_a_cte() {
	assert_same(array('WITH d AS (DELETE FROM t RETURNING *) SELECT * FROM d WHERE id > 1'),
		SqlEditor::unsafeStatements('WITH d AS (DELETE FROM t RETURNING *) SELECT * FROM d WHERE id > 1'));
	assert_same(array(), SqlEditor::unsafeStatements('WITH d AS (DELETE FROM t WHERE a RETURNING *) SELECT * FROM d'));
}

function test_truncate() {
	assert_same(array('TRUNCATE t'), SqlEditor::unsafeStatements('TRUNCATE t'));
	assert_same(array('truncate table a, b restart identity'), SqlEditor::unsafeStatements('/* x */ truncate table a, b restart identity'));
}

function test_only_the_unsafe_statements_are_listed() {
	assert_same(array('TRUNCATE b', 'DELETE FROM c'),
		SqlEditor::unsafeStatements("SELECT 1; DELETE FROM a WHERE id = 1; TRUNCATE b; DELETE FROM c"));
}

function test_explain_analyze_still_counts() {
	assert_same(array('EXPLAIN (ANALYZE, BUFFERS) DELETE FROM t'),
		SqlEditor::unsafeStatements('EXPLAIN (ANALYZE, BUFFERS) DELETE FROM t'));
}

function test_delete_and_truncate_as_other_words_are_fine() {
	foreach (array(
		"SELECT 'delete from t; truncate t'",
		"-- delete from t\nSELECT 1",
		"/* truncate t */ SELECT 1",
		'SELECT "delete from t" FROM x',
		'CREATE TABLE c (p int REFERENCES p ON DELETE CASCADE)',
		'GRANT DELETE, TRUNCATE ON t TO r',
		'REVOKE TRUNCATE ON t FROM r',
		'CREATE TRIGGER g BEFORE DELETE OR TRUNCATE ON t FOR EACH STATEMENT EXECUTE FUNCTION f()',
		"CREATE FUNCTION f() RETURNS void AS \$\$ DELETE FROM t; TRUNCATE u; \$\$ LANGUAGE sql",
		'CREATE POLICY p ON t FOR DELETE USING (true)',
		'SELECT deleted, truncated FROM log',
		'SELECT delete FROM t',
		'SELECT a, b AS delete FROM t',
		'CREATE RULE r AS ON DELETE TO t DO INSTEAD DELETE FROM u',
	) as $sql) {
		assert_same(array(), SqlEditor::unsafeStatements($sql), $sql);
	}
}

function test_long_statement_is_shortened() {
	$sql = 'DELETE FROM t USING ' . str_repeat('u, ', 100) . 'v';
	$out = SqlEditor::unsafeStatements($sql);
	assert_same(1, count($out));
	assert_true(mb_strlen($out[0], 'UTF-8') <= 201, 'shortened: ' . mb_strlen($out[0], 'UTF-8'));
	assert_true(substr($out[0], -3) === "\u{2026}", 'ends in an ellipsis');
}

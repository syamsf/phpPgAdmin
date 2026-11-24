// Browser checks for dialogs: row edit as a side panel, row delete and drop
// confirmations as modals.  node dialog.mjs [base]
import puppeteer from 'puppeteer-core';
import crypto from 'crypto';
import fs from 'fs';
import os from 'os';
import path from 'path';

const BASE = (process.argv[2] || 'http://127.0.0.1:8080/').replace(/\/?$/, '/');
const OUT = (process.env.SHOTS || path.join(os.tmpdir(), 'ppa-shots', 'dialog')) + '/';
fs.mkdirSync(OUT, { recursive: true });

const SERVER = 'db:5432:allow';
const Q = encodeURIComponent(SERVER);
const TABLE = 'dlg_test';
const BROWSE = `${BASE}display.php?server=${Q}&database=ppa_test&schema=public&subject=table&table=${TABLE}`;

const browser = await puppeteer.launch({ executablePath: process.env.CHROME || '/usr/bin/google-chrome', headless: true, args: ['--no-sandbox'] });
const page = await browser.newPage();
await page.setExtraHTTPHeaders({'Remote-User': 'ppa-test', 'Remote-Groups': 'role-admin'});
await page.setViewport({ width: 1280, height: 800 });

const errors = [];
page.on('pageerror', (e) => errors.push('pageerror: ' + e.message));
page.on('console', (m) => { if (m.type() === 'error') errors.push('console.error: ' + m.text()); });
let confirmAnswer = false, confirms = 0;
page.on('dialog', async (d) => { confirms++; if (confirmAnswer) await d.accept(); else await d.dismiss(); });

const results = [];
const check = (ok, what) => results.push((ok ? 'ok    ' : 'FAIL  ') + what);
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const idle = () => page.waitForNetworkIdle({ idleTime: 300, timeout: 15000 }).catch(() => {});
const dialogOpen = (kind) => page.evaluate((k) => !!document.querySelector('dialog.ppa-dialog-' + k + '[open]'), kind);
const anyDialog = () => page.evaluate(() => !!document.querySelector('dialog.ppa-dialog'));
const cell = (id) => page.evaluate((id) => {
	for (const tr of document.querySelectorAll('table#data tbody tr, table#data tr')) {
		const tds = [...tr.querySelectorAll('td')].map((td) => td.innerText.trim());
		if (tds.includes(String(id))) return tds.join('|');
	}
	return null;
}, id);
// The row's link exactly: key[id]=2 must not match key[id]=20.
const rowLink = (action, id) => `a[href*="action=${action}"][href*="key%5Bid%5D=${id}&"], a[href*="action=${action}"][href$="key%5Bid%5D=${id}"]`;

async function sql(query) {
	await page.evaluate(async (q, server) => {
		const body = new URLSearchParams({ ppa_csrf: document.querySelector('meta[name="ppa-csrf"]').content,  server, database: 'ppa_test', query: q });
		await fetch('sql.php', { method: 'POST', body });
	}, query, SERVER);
}

try {
	await page.goto(BASE + 'intro.php', { waitUntil: 'networkidle0' });
	await page.evaluate(async (server, pw) => {
		await fetch('redirect.php', { method: 'POST', body: new URLSearchParams({ ppa_csrf: document.querySelector('meta[name="ppa-csrf"]').content,  subject: 'server', server, loginServer: server, loginUsername: 'ppa', ['loginPassword_' + pw]: 'ppa', loginSubmit: 'Login' }) });
	}, SERVER, crypto.createHash('md5').update(SERVER).digest('hex'));
	// The login renews the CSRF token, so take the page's new one.
	await page.goto(BASE + 'intro.php', { waitUntil: 'networkidle0' });
	await sql(`DROP TABLE IF EXISTS public.${TABLE}; CREATE TABLE public.${TABLE} (id int PRIMARY KEY, name text NOT NULL, note text);
		INSERT INTO public.${TABLE} SELECT i, 'row ' || i, NULL FROM generate_series(1, 10) i;`);

	await page.goto(BROWSE, { waitUntil: 'networkidle0' });
	const url = page.url();
	await page.evaluate(() => { window.__marker = 1; window.scrollTo(0, 400); });

	// Edit: side panel
	await page.click(rowLink('confeditrow', 2));
	await page.waitForSelector('dialog.ppa-dialog-panel[open]', { timeout: 5000 }).catch(() => {});
	check(await dialogOpen('panel'), 'Edit opens a side panel');
	check(page.url() === url && await page.evaluate(() => window.__marker === 1), 'the page underneath stays');
	check(await page.$eval('dialog.ppa-dialog h2', (h) => h.textContent.trim().length > 0).catch(() => false), 'panel has the page title as heading');
	check(await page.evaluate(() => !document.querySelector('dialog .trail, dialog .topbar, dialog nav.tabs')), 'no breadcrumbs or tabs in the panel');
	check(await page.evaluate(() => document.querySelector('dialog').contains(document.activeElement)), 'focus moves into the panel');
	await sleep(300); await page.screenshot({ path: OUT + 'edit-panel.png' });

	await page.keyboard.press('Escape'); await sleep(200);
	check(!(await anyDialog()), 'Esc closes an untouched panel');

	// Unsaved changes: Esc asks first
	await page.click(rowLink('confeditrow', 2));
	await page.waitForSelector('dialog.ppa-dialog-panel[open]');
	await page.evaluate(() => {
		const f = document.querySelector('dialog [name="values[name]"]');
		f.focus(); f.select();
	});
	await page.keyboard.type('renamed two');
	confirms = 0; confirmAnswer = false;
	await page.keyboard.press('Escape'); await sleep(200);
	check(confirms === 1 && await dialogOpen('panel'), 'Esc with changes asks, and Cancel keeps the panel');

	// Save
	const scrollBefore = await page.evaluate(() => window.scrollY);
	await page.click('dialog input[type=submit][name=save]');
	await idle(); await sleep(300);
	check(!(await anyDialog()), 'Save closes the panel');
	check(/renamed two/.test(await cell(2) || ''), 'the grid shows the new value: ' + await cell(2));
	check(await page.evaluate(() => [...document.querySelectorAll('#ppa-main p.message')].some((p) => p.getAttribute('role') === 'status')), 'success message shown on the page');
	check(page.url() === url && await page.evaluate(() => window.__marker === 1), 'still the same page, no reload');
	check(Math.abs(await page.evaluate(() => window.scrollY) - scrollBefore) < 5, 'scroll position kept');

	// Save that fails stays in the panel
	await page.click(rowLink('confeditrow', 3));
	await page.waitForSelector('dialog.ppa-dialog-panel[open]');
	await page.evaluate(() => {
		const f = document.querySelector('dialog [name="values[id]"]');
		f.value = '1';   // duplicate primary key
		f.dispatchEvent(new Event('input', { bubbles: true }));
	});
	await page.click('dialog input[type=submit][name=save]');
	await idle(); await sleep(300);
	check(await dialogOpen('panel'), 'a failed save stays in the panel');
	check(await page.evaluate(() => !!document.querySelector('dialog p.message.error')), 'with the error message');
	check(await page.evaluate(() => !!document.querySelector('dialog input[name=save]')), 'and the form to fix it');
	await sleep(300); await page.screenshot({ path: OUT + 'edit-error.png' });
	confirmAnswer = true;
	await page.click('dialog .ppa-dialog-close'); await sleep(200);
	check(!(await anyDialog()), 'close button closes it (after confirming)');
	confirmAnswer = false;

	// Cancel button closes without a request
	await page.click(rowLink('confeditrow', 4));
	await page.waitForSelector('dialog.ppa-dialog-panel[open]');
	let posts = 0;
	const countPosts = (r) => { if (r.method() === 'POST') posts++; };
	page.on('request', countPosts);
	await page.click('dialog input[type=submit][name=cancel]'); await sleep(300);
	page.off('request', countPosts);
	check(!(await anyDialog()) && posts === 0, 'Cancel closes the panel without sending anything');

	// Delete: modal
	await page.click(rowLink('confdelrow', 5));
	await page.waitForSelector('dialog.ppa-dialog-modal[open]', { timeout: 5000 }).catch(() => {});
	check(await dialogOpen('modal'), 'Delete opens a modal');
	check(await page.evaluate(() => document.activeElement && document.activeElement.name === 'no'), 'focus starts on No');
	check(await page.evaluate(() => !!document.querySelector('dialog input.danger[name=yes]')), 'Yes is marked as dangerous');
	await sleep(300); await page.screenshot({ path: OUT + 'delete-modal.png' });
	await page.click('dialog input[name=no]'); await sleep(200);
	check(!(await anyDialog()) && await cell(5) !== null, 'No closes it and keeps the row');
	await page.click(rowLink('confdelrow', 5));
	await page.waitForSelector('dialog.ppa-dialog-modal[open]');
	await page.click('dialog input[name=yes]');
	await idle(); await sleep(300);
	check(!(await anyDialog()) && await cell(5) === null, 'Yes deletes the row and closes the modal');
	check(page.url() === url, 'still on the same page');

	// Clicking the backdrop closes a modal
	await page.click(rowLink('confdelrow', 6));
	await page.waitForSelector('dialog.ppa-dialog-modal[open]');
	await page.mouse.click(5, 790); await sleep(200);
	check(!(await anyDialog()), 'clicking outside closes the modal');

	// Modifier click still opens the page itself
	const href = await page.$eval(rowLink('confeditrow', 7), (a) => a.href);
	await page.goto(href, { waitUntil: 'networkidle0' });
	check(await page.evaluate(() => !!document.querySelector('#ppa-main input[name=save]') && !document.querySelector('dialog')), 'the edit page still works on its own');

	// The table's query box takes any query; Edit and Delete find the row in
	// this table by its key, so they are only offered when the key comes
	// straight from this table.
	await sql(`DROP TABLE IF EXISTS public.${TABLE}_other; CREATE TABLE public.${TABLE}_other (id int PRIMARY KEY, name text NOT NULL, ref int);
		INSERT INTO public.${TABLE}_other SELECT i, 'other ' || i, 11 - i FROM generate_series(1, 10) i;`);
	await page.goto(BROWSE, { waitUntil: 'networkidle0' });
	const runQuery = async (q) => {
		await page.evaluate((q) => {
			const f = document.querySelector('#ppa-main form.sql-query-form');
			f.querySelector('textarea[name=query]').value = q;
			const cm = f.querySelector('.CodeMirror');
			if (cm && cm.CodeMirror) cm.CodeMirror.setValue(q);
			f.querySelector('input[type=submit]').click();
		}, q);
		await idle(); await sleep(200);
	};
	const editKeys = () => page.$$eval('#ppa-main table#data a[href*="action=confeditrow"]', (l) => l.map((a) => new URL(a.href).searchParams.get('key[id]')).sort());
	const noKeyHint = () => page.evaluate(() => !!document.querySelector('#ppa-main .grid-no-key'));
	await runQuery(`SELECT * FROM public.${TABLE} WHERE id IN (2, 3)`);
	check(JSON.stringify(await editKeys()) === '["2","3"]' && !(await noKeyHint()), 'query on this table: Edit for its rows');
	for (const [what, q] of [
		['another table', `SELECT * FROM public.${TABLE}_other WHERE id = 7`],
		['a join with two id columns', `SELECT t.*, o.* FROM public.${TABLE} t JOIN public.${TABLE}_other o ON o.ref = t.id WHERE t.id = 2`],
		['another column named id', `SELECT name, ref AS id FROM public.${TABLE}_other WHERE id = 7`],
	]) {
		await runQuery(q);
		check((await editKeys()).length === 0 && !(await page.$('#ppa-main a[href*="action=confdelrow"]')) && await noKeyHint(),
			'query on ' + what + ': no Edit or Delete, and a hint why');
	}

	// Back to a query's results after saving a row there shows the saved value
	await runQuery(`SELECT * FROM public.${TABLE} WHERE id = 2`);
	await page.click(rowLink('confeditrow', 2));
	await page.waitForSelector('dialog.ppa-dialog-panel[open]');
	await page.evaluate(() => { document.querySelector('dialog [name="values[name]"]').value = 'saved before back'; });
	await page.click('dialog input[type=submit][name=save]');
	await idle(); await sleep(300);
	await runQuery(`SELECT * FROM public.${TABLE} WHERE id = 4`);
	await page.goBack(); await idle(); await sleep(300);
	check(/saved before back/.test(await cell(2) || ''), 'Back after saving in the panel shows the saved value: ' + await cell(2));

	// The SQL tab's results: rows of one table with its key get Edit and
	// Delete too, and saving comes back to the same results.  Ids 8 and 9:
	// the checks above edit 2-4 and delete 5 and 6.
	await page.goto(`${BASE}database.php?subject=database&server=${Q}&database=ppa_test&action=sql&new=1`, { waitUntil: 'networkidle0' });
	const runSqlTab = async (q, path) => {
		await page.evaluate((q, path) => {
			const f = document.querySelector('#ppa-main form.sql-editor-form');
			f.querySelector('#paginate').checked = true;
			f.querySelector('[name=search_path]').value = path;
			f.querySelector('textarea[name=query]').value = q;
			const cm = f.querySelector('.CodeMirror');
			if (cm && cm.CodeMirror) cm.CodeMirror.setValue(q);
			f.querySelector('input[type=submit][name=execute]').click();
		}, q, path);
		await idle(); await sleep(200);
	};
	const sqlTabState = () => page.evaluate(() => {
		const f = document.querySelector('#ppa-main form.sql-editor-form');
		const cm = f && f.querySelector('.CodeMirror');
		return {
			title: (document.querySelector('#ppa-main h2') || {}).textContent?.trim(),
			query: cm && cm.CodeMirror ? cm.CodeMirror.getValue() : null,
			path: f ? f.querySelector('[name=search_path]').value : null,
		};
	});
	const sqlTabQuery = 'SELECT id, name FROM dlg_test WHERE id IN (8, 9) ORDER BY id';
	const onSqlResults = async (what) => {
		const s = await sqlTabState();
		check(s.title === 'Query Results' && s.query === sqlTabQuery && s.path === 'shop,public',
			what + ': still the SQL tab results, same query and search path: ' + JSON.stringify(s));
	};
	await runSqlTab(sqlTabQuery, 'shop,public');
	check(JSON.stringify(await editKeys()) === '["8","9"]' && !(await noKeyHint()), 'SQL tab, one table: Edit for its rows');
	await page.click(rowLink('confeditrow', 8));
	await page.waitForSelector('dialog.ppa-dialog-panel[open]', { timeout: 5000 }).catch(() => {});
	check(await dialogOpen('panel'), 'SQL tab: Edit opens the side panel');
	check(await page.$eval('dialog [name="values[id]"]', (e) => e.value).catch(() => null) === '8', 'SQL tab: the panel has the row clicked');
	await sleep(300); await page.screenshot({ path: OUT + 'sqltab-edit-panel.png' });
	await page.evaluate(() => { document.querySelector('dialog [name="values[name]"]').value = 'saved from sql tab'; });
	await page.click('dialog input[type=submit][name=save]');
	await idle(); await sleep(300);
	check(!(await anyDialog()), 'SQL tab: saving closes the panel');
	check(/saved from sql tab/.test(await cell(8) || ''), 'SQL tab: the saved value is shown: ' + await cell(8));
	check(/row 9/.test(await cell(9) || ''), 'SQL tab: the other row is unchanged: ' + await cell(9));
	await onSqlResults('after Save');

	// Delete asks first; No keeps the row
	await page.click(rowLink('confdelrow', 9));
	await page.waitForSelector('dialog.ppa-dialog-modal[open]', { timeout: 5000 }).catch(() => {});
	check(await dialogOpen('modal'), 'SQL tab: Delete opens a modal');
	check(await page.evaluate(() => document.activeElement && document.activeElement.name === 'no'), 'SQL tab: focus starts on No');
	await page.click('dialog input[name=no]'); await sleep(200);
	check(!(await anyDialog()) && /row 9/.test(await cell(9) || ''), 'SQL tab: No closes it and keeps the row');
	// Yes deletes it and comes back to the same results
	await page.click(rowLink('confdelrow', 9));
	await page.waitForSelector('dialog.ppa-dialog-modal[open]', { timeout: 5000 }).catch(() => {});
	await page.click('dialog input[name=yes]');
	await idle(); await sleep(300);
	check(!(await anyDialog()) && (await cell(9)) === null && /saved from sql tab/.test(await cell(8) || ''), 'SQL tab: Yes deletes the row: ' + await cell(9));
	await onSqlResults('after Delete');
	await runSqlTab('SELECT count(*) AS n FROM dlg_test WHERE id = 9', 'public');
	check(await page.evaluate(() => [...document.querySelectorAll('table#data tbody td')].some((td) => td.innerText.trim() === '0')), 'SQL tab: row 9 is gone from the table');

	// Columns from two tables stay read-only
	await runSqlTab(`SELECT t.id, o.name FROM dlg_test t JOIN dlg_test_other o ON o.id = t.id WHERE t.id = 2`, 'public');
	check((await editKeys()).length === 0 && !(await page.$('#ppa-main a[href*="action=confdelrow"]')) && await noKeyHint(),
		'SQL tab, a join: no Edit or Delete, and a hint why');
	await sql(`DROP TABLE IF EXISTS public.${TABLE}_other`);

	// Drop confirmations from a list open as a modal too
	await page.goto(`${BASE}tables.php?server=${Q}&database=ppa_test&schema=public&subject=schema`, { waitUntil: 'networkidle0' });
	const dropLink = await page.evaluateHandle((t) => [...document.querySelectorAll('a[href*="action=confirm_drop"]')].find((a) => a.href.includes('table=' + t)), TABLE);
	// Drop is in the row's "more actions" menu, last and marked as dangerous
	check(await dropLink.evaluate((a) => !!a.closest('details.ppa-menu') && a.classList.contains('danger')), 'Drop is in the more-actions menu, marked danger');
	await dropLink.evaluate((a) => a.closest('details.ppa-menu').querySelector('summary').click());
	await page.waitForSelector('details.ppa-menu[open] .ppa-menu-list a', { visible: true, timeout: 3000 }).catch(() => {});
	await dropLink.asElement().click();
	await page.waitForSelector('dialog.ppa-dialog-modal[open]', { timeout: 5000 }).catch(() => {});
	check(await dialogOpen('modal'), 'Drop table opens a modal');
	check(await page.evaluate(() => document.activeElement && document.activeElement.name === 'cancel'), 'focus on Cancel');
	await sleep(300); await page.screenshot({ path: OUT + 'drop-modal.png' });
	await page.click('dialog input.danger');
	await idle(); await sleep(500);
	check(!(await anyDialog()), 'dropping closes the modal');
	check(!(await page.evaluate((t) => document.querySelector('#ppa-main').innerText.includes(t + '\n'), TABLE)) && /tables\.php/.test(page.url()), 'table list is shown again without it');

	// FK autocomplete on the insert form: a jQuery POST that needs the CSRF header
	await page.goto(`${BASE}tables.php?server=${Q}&database=ppa_test&schema=shop&table=orders&subject=table&action=confinsertrow`, { waitUntil: 'networkidle0' });
	const fkField = await page.$('input[id^="attr_"][name^="values"], #row_att_2 input, input[name="values[customer_id]"]');
	if (fkField) {
		const fkInfo = await page.evaluate(() => {
			const el = [...document.querySelectorAll('input[id^="attr_"]')].find((i) => /customer_id/.test(i.name) || /customer_id/.test((i.closest('tr') || {}).innerText || ''));
			if (!el) return null;
			el.focus(); return el.id;
		});
		check(!!fkInfo, 'insert form has the customer_id field');
		if (fkInfo) {
			await page.keyboard.type('1');
			await page.waitForFunction(() => document.querySelector('#fklist') && document.querySelector('#fklist').querySelectorAll('tr').length > 0, { timeout: 5000 }).catch(() => {});
			check(await page.evaluate(() => document.querySelectorAll('#fklist tr').length > 0), 'FK autocomplete lists matching rows');
		}
	} else check(false, 'insert form has the customer_id field');

	// Dark theme and phone
	await sql(`CREATE TABLE public.${TABLE} (id int PRIMARY KEY, name text NOT NULL, note text); INSERT INTO public.${TABLE} VALUES (1, 'one', 'x');`);
	await page.goto(BROWSE + '&theme=dark', { waitUntil: 'networkidle0' });
	await page.click(rowLink('confeditrow', 1));
	await page.waitForSelector('dialog.ppa-dialog-panel[open]');
	await sleep(300);
	await page.screenshot({ path: OUT + 'edit-panel-dark.png' });
	await page.keyboard.press('Escape');
	await page.goto(BASE + 'intro.php?theme=default', { waitUntil: 'networkidle0' });
	await page.setViewport({ width: 390, height: 844, isMobile: true, hasTouch: true });
	await page.goto(BROWSE, { waitUntil: 'networkidle0' });
	await page.tap(rowLink('confeditrow', 1));
	await page.waitForSelector('dialog.ppa-dialog-panel[open]');
	await sleep(300);
	const w = await page.$eval('dialog.ppa-dialog-panel', (d) => d.getBoundingClientRect().width);
	check(w >= 380, 'panel fills a phone screen (' + w + 'px)');
	await page.screenshot({ path: OUT + 'edit-panel-phone.png' });
	await sql(`DROP TABLE IF EXISTS public.${TABLE}`);
} catch (e) {
	results.push('ERROR ' + (e && e.stack || e));
	await page.screenshot({ path: OUT + 'error.png' }).catch(() => {});
}

console.log(results.join('\n'));
console.log('\nJS errors:\n' + (errors.length ? errors.join('\n') : '(none)'));
await browser.close();
process.exit(results.some((r) => !r.startsWith('ok')) || errors.length ? 1 : 0);

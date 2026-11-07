// Takes the screenshots in docs/screenshot from a running test site with
// the fixtures loaded (KEEP=1 tests/run.sh, or the compose file directly).
// It adds some sample rows first, so only point it at a throwaway database.
//
//   node tests/browser/screenshots.mjs [base] [output dir]
import puppeteer from 'puppeteer-core';
import crypto from 'crypto';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const here = path.dirname(fileURLToPath(import.meta.url));
const BASE = (process.argv[2] || 'http://127.0.0.1:8080/').replace(/\/?$/, '/');
const OUT = path.resolve(process.argv[3] || path.join(here, '../../docs/screenshot'));
fs.mkdirSync(OUT, { recursive: true });

const SERVER = 'db:5432:allow';
const Q = encodeURIComponent(SERVER);
const DB = `server=${Q}&database=ppa_test`;
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

const browser = await puppeteer.launch({ executablePath: process.env.CHROME || '/usr/bin/google-chrome', headless: true, args: ['--no-sandbox', '--hide-scrollbars'] });
const page = await browser.newPage();
await page.setViewport({ width: 1280, height: 760 });

async function shot(name) {
	await sleep(400);   // let dialogs and popups finish their animation
	await page.screenshot({ path: path.join(OUT, name + '.png') });
	console.log('wrote', path.join(OUT, name + '.png'));
}
async function go(url) {
	await page.goto(BASE + url, { waitUntil: 'networkidle0' });
}
async function sql(query) {
	await page.evaluate(async (q, server) => {
		await fetch('sql.php', { method: 'POST', body: new URLSearchParams({ server, database: 'ppa_test', query: q }) });
	}, query, SERVER);
}
async function openTree(...names) {
	for (const name of names) {
		const link = await page.evaluateHandle((t) => [...document.querySelectorAll('#ppa-tree .ppa-label')].find((a) => a.textContent === t && a.offsetParent), name);
		const li = await link.evaluateHandle((a) => a.closest('li'));
		const open = await li.evaluate((l) => l.getAttribute('aria-expanded') === 'true');
		if (!open) await li.evaluate((l) => l.querySelector('.ppa-twisty').click());
		await page.waitForNetworkIdle({ idleTime: 200 }).catch(() => {});
	}
}

// Log in and add sample data.
await go('intro.php');
await page.evaluate(async (server, pw) => {
	await fetch('redirect.php', { method: 'POST', body: new URLSearchParams({ subject: 'server', server, loginServer: server, loginUsername: 'ppa', ['loginPassword_' + pw]: 'ppa', loginSubmit: 'Login' }) });
}, SERVER, crypto.createHash('md5').update(SERVER).digest('hex'));
await sql(`
	INSERT INTO shop.customer (name, email)
	SELECT n, lower(n) || '@example.com' FROM unnest(ARRAY['Dewi','Eko','Fatima','Gita','Hana','Ivan','Joko','Kartika']) AS n
	WHERE NOT EXISTS (SELECT 1 FROM shop.customer WHERE name = 'Dewi');
	INSERT INTO shop.orders (customer_id, status, total, note, data)
	SELECT 1 + (i * 7) % 11, (ARRAY['new','paid','shipped']::shop.order_status[])[1 + i % 3],
		round((5 + (i * 37) % 240)::numeric + 0.99, 2),
		CASE WHEN i % 4 = 0 THEN 'gift wrap' END,
		jsonb_build_object('items', 1 + i % 5)
	FROM generate_series(1, 40) i
	WHERE (SELECT count(*) FROM shop.orders) < 10;
	-- The fixtures have an HTML-escaping test name; not for the docs.
	UPDATE shop.customer SET name = 'Chen' WHERE name LIKE 'Chen%';
	REFRESH MATERIALIZED VIEW shop.order_totals;
	ANALYZE shop.orders;`);

// 1. Browsing a table, with the tree open.
await go(`display.php?${DB}&schema=shop&subject=table&table=orders`);
await openTree('Test', 'ppa_test', 'Schemas', 'shop', 'Tables');
await shot('browse');

// 2. The SQL editor suggesting tables.
await go(`database.php?${DB}&subject=database&action=sql`);
await page.evaluate(() => {
	const cm = document.querySelector('.CodeMirror').CodeMirror;
	cm.setValue('SELECT c.name, count(o.id) AS orders, sum(o.total) AS total\nFROM shop.customer c\nJOIN shop');
	cm.focus();
	cm.setCursor(cm.lineCount(), 0);
});
await page.keyboard.type('.');
await page.waitForSelector('.CodeMirror-hints').catch(() => {});
await shot('sql-editor');

// 3. Results under the editor.
await page.keyboard.press('Escape');
await page.evaluate(() => {
	const cm = document.querySelector('.CodeMirror').CodeMirror;
	cm.setValue('SELECT c.name, count(o.id) AS orders, sum(o.total) AS total\nFROM shop.customer c\nJOIN shop.orders o ON o.customer_id = c.id\nGROUP BY c.name\nORDER BY total DESC;');
	const p = document.querySelector('input[name=paginate]');
	if (p) p.checked = false;
});
await Promise.all([page.click('input[name=execute]'), page.waitForNetworkIdle({ idleTime: 300 })]);
await shot('sql-results');

// 4. Editing a row in the side panel.
await go(`display.php?${DB}&schema=shop&subject=table&table=orders`);
await page.click('a[href*="action=confeditrow"]');
await page.waitForSelector('dialog.ppa-dialog-panel[open]');
await shot('edit-panel');

// 5. Dark theme.
await go(`display.php?${DB}&schema=shop&subject=table&table=orders&theme=dark`);
await shot('dark');
await go('intro.php?theme=default');

// 6. Phone: a page, and the sidebar slid in over it.
await page.setViewport({ width: 390, height: 780, isMobile: true, hasTouch: true, deviceScaleFactor: 2 });
await go(`display.php?${DB}&schema=shop&subject=table&table=orders`);
await shot('phone');
await page.tap('#ppa-sidebar-toggle');
await shot('phone-sidebar');

await browser.close();

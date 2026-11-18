// Browser checks for the saved-login dropdown on the login page (board 1,
// js/vault.js).  node vault.mjs [base]
// Signs in as alice (sso headers). tests/vault.py leaves her saved logins
// for ppa_other; without one, this saves one first.
import puppeteer from 'puppeteer-core';
import fs from 'fs';
import os from 'os';
import path from 'path';

const BASE = (process.argv[2] || 'http://127.0.0.1:8080/').replace(/\/?$/, '/');
const OUT = (process.env.SHOTS || path.join(os.tmpdir(), 'ppa-shots', 'vault')) + '/';
fs.mkdirSync(OUT, { recursive: true });

const SERVER = 'db:5432:allow:ppa_other';
const LOGIN = `${BASE}redirect.php?subject=database&server=${encodeURIComponent(SERVER)}&database=ppa_other`;
const LOGOUT = `${BASE}servers.php?action=logout&logoutServer=${encodeURIComponent(SERVER)}`;

const browser = await puppeteer.launch({ executablePath: process.env.CHROME || '/usr/bin/google-chrome', headless: true, args: ['--no-sandbox'] });
const page = await browser.newPage();
await page.setExtraHTTPHeaders({ 'Remote-User': 'alice', 'Remote-Groups': '' });
await page.setViewport({ width: 1280, height: 860 });

const errors = [];
page.on('pageerror', (e) => errors.push('pageerror: ' + e.message));
page.on('console', (m) => { if (m.type() === 'error') errors.push('console.error: ' + m.text()); });

const results = [];
const check = (ok, what) => results.push((ok ? 'ok    ' : 'FAIL  ') + what);
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const idle = () => page.waitForNetworkIdle({ idleTime: 300, timeout: 15000 }).catch(() => {});
const BUTTON = 'button[aria-haspopup="listbox"]';
const expanded = () => page.$eval(BUTTON, (b) => b.getAttribute('aria-expanded'));
const listVisible = () => page.$eval('ul[role="listbox"]', (l) => !l.hidden && l.offsetParent !== null);

try {
	await page.goto(LOGOUT, { waitUntil: 'networkidle0' });
	await page.goto(LOGIN, { waitUntil: 'networkidle0' });
	if (!(await page.$('#loginCredential'))) {
		// No saved login yet: log in by hand with "Save this login", then out.
		await page.type('#loginUsername', 'vault_rot');
		await page.type('#loginPassword', 'Rot-pass-1');
		await page.click('#loginSave');
		await page.type('#loginSaveLabel', 'rot');
		await Promise.all([page.click('input[name=loginSubmit]'), idle()]);
		await page.goto(LOGOUT, { waitUntil: 'networkidle0' });
		await page.goto(LOGIN, { waitUntil: 'networkidle0' });
	}

	check(await page.$(BUTTON) !== null, 'the saved-login button is there');
	check(await page.$eval('#loginCredential', (s) => s.hidden && s.offsetParent === null), 'the native select is hidden');
	check(await page.$eval('ul[role="listbox"] [role="presentation"]', (li) => li.textContent.trim() === 'Mine').catch(() => false),
		'the list has a Mine group header');
	check(await expanded() === 'false' && !(await listVisible()), 'the list starts closed');
	check(await page.$eval('label[for="loginCredential-button"]', (l) => l.textContent.trim() === 'Saved login').catch(() => false),
		'the field label names the button');

	// ArrowDown opens, Enter picks the first item.
	await page.focus(BUTTON);
	await page.keyboard.press('ArrowDown');
	await sleep(100);
	check(await expanded() === 'true' && await listVisible(), 'ArrowDown opens the list');
	await page.screenshot({ path: OUT + 'vault-login.png' });
	const first = await page.$eval('ul[role="listbox"] [role="option"]', (li) => li.getAttribute('data-value'));
	await page.keyboard.press('ArrowDown');
	await page.keyboard.press('ArrowUp');
	await page.keyboard.press('Enter');
	await sleep(100);
	check(await page.$eval('#loginCredential', (s) => s.value) === first, '#loginCredential has the first item\'s value');
	check(await expanded() === 'false' && !(await listVisible()), 'Enter closes the list');
	check(await page.evaluate((b) => document.activeElement === document.querySelector(b), BUTTON), 'focus is back on the button');
	check((await page.$eval(BUTTON, (b) => b.textContent)).includes('vault_rot'), 'the button shows the chosen login');

	// Escape closes and returns focus.
	await page.keyboard.press('Enter');
	await sleep(100);
	check(await listVisible(), 'Enter on the button opens the list');
	await page.keyboard.press('Escape');
	await sleep(100);
	check(await expanded() === 'false' && !(await listVisible()), 'Escape closes the list');
	check(await page.evaluate((b) => document.activeElement === document.querySelector(b), BUTTON), 'Escape returns focus to the button');

	// A click outside closes it.
	await page.click(BUTTON);
	await sleep(100);
	check(await listVisible(), 'a click opens the list');
	await page.click('#vault-manual-h');
	await sleep(100);
	check(!(await listVisible()), 'a click outside closes the list');

	// The page swapped in by the app shell gets the dropdown too.
	await page.goto(BASE + 'intro.php', { waitUntil: 'networkidle0' });
	await page.evaluate((href) => {
		window.__marker = 1;
		const a = document.createElement('a');
		a.href = href;
		a.id = 'vault-test-link';
		a.textContent = 'go';
		document.getElementById('ppa-main').appendChild(a);
	}, LOGIN);
	await Promise.all([page.click('#vault-test-link'), idle()]);
	await sleep(200);
	check(await page.evaluate(() => window.__marker === 1), 'the login page came in place (app shell)');
	check(await page.$(BUTTON) !== null && await page.$eval('#loginCredential', (s) => s.hidden), 'the swapped-in page has the dropdown');

	// Submitting logs in with the chosen saved login.
	await Promise.all([page.click('#login_saved_form button[type=submit]'), idle()]);
	await idle();
	check(await page.$('#loginUsername') === null, 'the saved login logs in');
	check(await page.$eval('.topbar .username', (u) => u.textContent).catch(() => '') === 'vault_rot', 'the top bar shows vault_rot');
	check(!(await page.content()).includes('Rot-pass-1'), 'the password is nowhere in the page');
	await page.goto(LOGOUT, { waitUntil: 'networkidle0' });

	// Manage servers (board 6): the delete dialog's button waits for the typed key.
	await page.setExtraHTTPHeaders({ 'Remote-User': 'boss', 'Remote-Groups': 'role-admin' });
	await page.goto(BASE + 'servers_admin.php', { waitUntil: 'networkidle0' });
	if (!(await page.$('a[href*="key=br-db"]'))) {
		await page.goto(BASE + 'servers_admin.php?action=add', { waitUntil: 'networkidle0' });
		await page.type('#vault-skey', 'br-db');
		await page.type('#vault-sname', 'Browser DB');
		await page.type('#vault-shost', 'db');
		await page.select('#vault-sssl', 'disable');
		await page.$eval('#vault-sdb', (i) => { i.value = 'ppa_other'; });
		await Promise.all([page.click('button[value=save]'), idle()]);
	}
	check(await page.$('a[href*="key=br-db"]') !== null, 'the added server is in the list');
	await page.click('a[href*="action=delete"][href*="key=br-db"]');
	await page.waitForSelector('dialog[open] #vault-confirm-key', { timeout: 10000 });
	const go = () => page.$eval('#vault-confirm-go', (b) => b.disabled);
	check(await go() === true, 'the delete button starts disabled');
	await page.type('#vault-confirm-key', 'br-d');
	check(await go() === true, 'a partial key leaves it disabled');
	await page.type('#vault-confirm-key', 'b');
	check(await go() === false, 'the full key enables it');
	await page.screenshot({ path: OUT + 'servers-delete.png' });
	await Promise.all([page.click('#vault-confirm-go'), idle()]);
	await sleep(300);
	check(await page.$('a[href*="key=br-db"]') === null, 'the server is deleted');
} catch (e) {
	results.push('ERROR ' + (e && e.stack || e));
	await page.screenshot({ path: OUT + 'error.png' }).catch(() => {});
}

console.log(results.join('\n'));
console.log('\nJS errors:\n' + (errors.length ? errors.join('\n') : '(none)'));
await browser.close();
process.exit(results.some((r) => !r.startsWith('ok')) || errors.length ? 1 : 0);

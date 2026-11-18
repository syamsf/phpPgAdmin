/*
 * Saved-login dropdown on the login page (login.php, board 1).
 *
 * The page has a plain <select data-vault-select> that works without this
 * script. On every "ppa:load" (see js/app.js) each one is hidden and a
 * button with a listbox takes its place: label, Postgres user, access tag,
 * and a second line per login (last use, sharing, or a failed password with
 * a link to update it). Picking an item sets the select's value and fires
 * "change", so the form posts the same field as before.
 *
 * The handlers are delegated and bound once, at the top level. The last
 * one is for the share form of the Shared logins page (vault_admin.php).
 */
(function () {
	'use strict';

	var SVG = 'http://www.w3.org/2000/svg';

	function svg(paths, size, label) {
		var s = document.createElementNS(SVG, 'svg');
		s.setAttribute('width', size);
		s.setAttribute('height', size);
		s.setAttribute('viewBox', '0 0 24 24');
		s.setAttribute('fill', 'none');
		s.setAttribute('stroke', 'currentColor');
		s.setAttribute('stroke-width', '2');
		s.setAttribute('stroke-linecap', 'round');
		s.setAttribute('stroke-linejoin', 'round');
		s.setAttribute('focusable', 'false');
		if (label) {
			s.setAttribute('role', 'img');
			s.setAttribute('aria-label', label);
		} else {
			s.setAttribute('aria-hidden', 'true');
		}
		paths.forEach(function (d) {
			var p = document.createElementNS(SVG, 'path');
			p.setAttribute('d', d);
			s.appendChild(p);
		});
		return s;
	}

	function el(tag, cls, text) {
		var e = document.createElement(tag);
		if (cls) e.className = cls;
		if (text != null) e.textContent = text;
		return e;
	}

	function tag(option) {
		var access = option.getAttribute('data-access') || '';
		return el('span', 'vault-tag vault-tag-' + (access === 'read-only' ? 'ro' : 'rw'),
			option.getAttribute('data-access-text') || access);
	}

	/* What the button shows for the chosen login. */
	function fillButton(button, option) {
		var value = button.querySelector('.vault-select-value');
		value.textContent = '';
		if (!option) return;
		value.appendChild(el('strong', null, option.getAttribute('data-label') || option.textContent));
		value.appendChild(el('span', 'vault-select-user', option.getAttribute('data-user') || ''));
		value.appendChild(tag(option));
	}

	function upgrade(select) {
		if (select.getAttribute('data-vault-ready')) return;
		select.setAttribute('data-vault-ready', '1');
		var id = select.id || ('vault-select-' + Math.random().toString(36).slice(2));

		var wrap = el('div', 'vault-select');
		var button = el('button', 'vault-select-button');
		button.type = 'button';
		button.id = id + '-button';
		button.setAttribute('aria-haspopup', 'listbox');
		button.setAttribute('aria-expanded', 'false');
		button.setAttribute('aria-controls', id + '-listbox');
		button.appendChild(el('span', 'vault-select-value'));
		button.appendChild(svg(['M6 9l6 6 6-6'], 16));

		var list = el('ul', 'vault-select-list');
		list.id = id + '-listbox';
		list.setAttribute('role', 'listbox');
		list.setAttribute('aria-label', select.getAttribute('data-listbox-label') || '');
		list.tabIndex = -1;
		list.hidden = true;

		var fixText = select.getAttribute('data-fix-text') || '';
		var warnText = select.getAttribute('data-warning-text') || '';
		var n = 0;
		Array.prototype.forEach.call(select.children, function (group) {
			var options = group.tagName === 'OPTGROUP' ? group.children : [group];
			if (group.tagName === 'OPTGROUP') {
				list.appendChild(el('li', 'vault-select-group', group.label)).setAttribute('role', 'presentation');
			}
			Array.prototype.forEach.call(options, function (option) {
				var failed = option.getAttribute('data-failed') === '1';
				var li = el('li', 'vault-option' + (failed ? ' vault-option-failed' : ''));
				li.id = id + '-option-' + (n++);
				li.setAttribute('role', 'option');
				li.setAttribute('aria-selected', option.selected ? 'true' : 'false');
				li.setAttribute('data-value', option.value);

				var main = el('span', 'vault-option-main');
				var title = el('span', 'vault-option-title');
				if (failed) title.appendChild(svg(['M12 3l10 18H2z', 'M12 10v5', 'M12 18h.01'], 14, warnText));
				title.appendChild(el('strong', null, option.getAttribute('data-label') || option.textContent));
				main.appendChild(title);
				var meta = el('span', 'vault-option-meta', option.getAttribute('data-meta') || '');
				var fix = option.getAttribute('data-fix');
				if (failed && fix) {
					meta.appendChild(document.createTextNode(' · '));
					var a = el('a', 'vault-option-fix', fixText);
					a.setAttribute('href', fix);
					a.tabIndex = -1;
					meta.appendChild(a);
				}
				main.appendChild(meta);
				li.appendChild(main);
				li.appendChild(tag(option));
				list.appendChild(li);
			});
		});

		select.parentNode.insertBefore(wrap, select);
		wrap.appendChild(button);
		wrap.appendChild(list);
		wrap.appendChild(select);
		select.hidden = true;
		select.tabIndex = -1;
		// The field's label now names the button.
		var label = select.id && document.querySelector('label[for="' + select.id + '"]');
		if (label) label.htmlFor = button.id;

		fillButton(button, select.options[select.selectedIndex]);
	}

	function parts(node) {
		var wrap = node && node.closest ? node.closest('.vault-select') : null;
		if (!wrap) return null;
		return {
			wrap: wrap,
			button: wrap.querySelector('.vault-select-button'),
			list: wrap.querySelector('.vault-select-list'),
			select: wrap.querySelector('select[data-vault-select]')
		};
	}

	function items(p) {
		return Array.prototype.slice.call(p.list.querySelectorAll('[role="option"]'));
	}

	function setActive(p, li) {
		items(p).forEach(function (o) { o.classList.toggle('vault-option-active', o === li); });
		if (li) {
			p.list.setAttribute('aria-activedescendant', li.id);
			li.scrollIntoView({ block: 'nearest' });
		} else {
			p.list.removeAttribute('aria-activedescendant');
		}
	}

	function active(p) {
		var id = p.list.getAttribute('aria-activedescendant');
		return id ? document.getElementById(id) : null;
	}

	function open(p) {
		closeAll(p.wrap);
		p.list.hidden = false;
		p.button.setAttribute('aria-expanded', 'true');
		var all = items(p);
		var sel = all.filter(function (o) { return o.getAttribute('aria-selected') === 'true'; })[0];
		setActive(p, sel || all[0] || null);
		p.list.focus();
	}

	function close(p, focusButton) {
		if (p.list.hidden) return;
		p.list.hidden = true;
		p.button.setAttribute('aria-expanded', 'false');
		if (focusButton) p.button.focus();
	}

	function closeAll(except) {
		document.querySelectorAll('.vault-select').forEach(function (wrap) {
			if (wrap !== except) {
				var p = parts(wrap);
				if (p) close(p, false);
			}
		});
	}

	function choose(p, li) {
		var value = li.getAttribute('data-value');
		items(p).forEach(function (o) { o.setAttribute('aria-selected', o === li ? 'true' : 'false'); });
		p.select.value = value;
		fillButton(p.button, p.select.options[p.select.selectedIndex]);
		p.select.dispatchEvent(new Event('change', { bubbles: true }));
		close(p, true);
	}

	function move(p, step) {
		var all = items(p);
		if (!all.length) return;
		var i = all.indexOf(active(p));
		if (step === Infinity) i = all.length - 1;
		else if (step === -Infinity) i = 0;
		else i = Math.max(0, Math.min(all.length - 1, (i < 0 ? 0 : i + step)));
		setActive(p, all[i]);
	}

	document.addEventListener('ppa:load', function () {
		document.querySelectorAll('select[data-vault-select]').forEach(upgrade);
	});

	document.addEventListener('click', function (e) {
		var p = parts(e.target);
		if (!p) {
			closeAll(null);
			return;
		}
		if (e.target.closest('.vault-select-button')) {
			if (p.list.hidden) open(p);
			else close(p, true);
			return;
		}
		// The Update password link goes where it says.
		if (e.target.closest('a')) {
			close(p, false);
			return;
		}
		var li = e.target.closest('[role="option"]');
		if (li) choose(p, li);
	});

	document.addEventListener('keydown', function (e) {
		var p = parts(e.target);
		if (!p) return;
		if (e.target === p.button) {
			if (e.key === 'Enter' || e.key === ' ' || e.key === 'ArrowDown') {
				e.preventDefault();
				open(p);
			}
			return;
		}
		if (e.target !== p.list) return;
		switch (e.key) {
			case 'ArrowDown': e.preventDefault(); move(p, 1); break;
			case 'ArrowUp': e.preventDefault(); move(p, -1); break;
			case 'Home': e.preventDefault(); move(p, -Infinity); break;
			case 'End': e.preventDefault(); move(p, Infinity); break;
			case 'Enter':
			case ' ':
				e.preventDefault();
				if (active(p)) choose(p, active(p));
				break;
			case 'Escape':
				e.preventDefault();
				e.stopPropagation();
				close(p, true);
				break;
			case 'Tab':
				close(p, false);
				break;
		}
	});

	// Focus leaving the open list (a click elsewhere, the keyboard) closes it.
	document.addEventListener('focusout', function (e) {
		var p = parts(e.target);
		if (!p || e.target !== p.list) return;
		setTimeout(function () {
			if (!p.wrap.contains(document.activeElement)) close(p, false);
		}, 0);
	});

	// Shared logins panel (vault_admin.php): the name field's label follows
	// the User / Group choice, and so do its suggestions (users or groups).
	document.addEventListener('change', function (e) {
		var radio = e.target;
		if (!radio.matches || !radio.matches('input[data-vault-share-type]') || !radio.form) return;
		var label = radio.form.querySelector('label[for="vault-principal"]');
		if (label) label.textContent = radio.getAttribute('data-label');
		var input = radio.form.querySelector('#vault-principal');
		if (input && radio.getAttribute('data-list')) input.setAttribute('list', radio.getAttribute('data-list'));
	});

	// Shared login form (vault_admin.php): the Database field follows the
	// chosen server, a select of its databases when it has a fixed list,
	// otherwise a text box with its default database. "Replace password"
	// (#vault-password) focuses the password field.
	document.addEventListener('change', function (e) {
		var select = e.target;
		if (!select.matches || !select.matches('select[data-vault-dbs]') || !select.form) return;
		var option = select.options[select.selectedIndex];
		var old = select.form.querySelector('[name="database"]');
		if (!option || !old) return;
		var dbs = [];
		try { dbs = JSON.parse(option.getAttribute('data-dbs') || '[]'); } catch (err) { dbs = []; }
		var field;
		if (dbs.length) {
			field = document.createElement('select');
			dbs.forEach(function (db) {
				var o = document.createElement('option');
				o.value = db;
				o.textContent = db;
				if (db === old.value) o.selected = true;
				field.appendChild(o);
			});
		} else {
			field = document.createElement('input');
			field.type = 'text';
			field.maxLength = 63;
			field.autocomplete = 'off';
			field.value = option.getAttribute('data-default-db') || '';
		}
		field.id = old.id;
		field.name = 'database';
		field.required = true;
		old.parentNode.replaceChild(field, old);
	});
	document.addEventListener('ppa:load', function () {
		var field = document.getElementById('vault-password');
		if (field && /(^|[#&])vault-password$/.test(location.hash) && field.form && field.form.classList.contains('vault-shared-form')) {
			field.focus();
		}
	});
})();

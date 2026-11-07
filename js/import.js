/*
 * Table import (tblproperties.php?action=import): when a CSV or tab
 * separated file is picked, show its first rows and check that the names
 * on its first line are columns of the table, before anything is sent.
 */
(function () {
	'use strict';

	if (window.ppaImportPreview) return;
	window.ppaImportPreview = true;

	var MAX_ROWS = 8;
	var READ_BYTES = 65536;

	/* A small CSV reader: quotes, doubled quotes, newlines inside quotes. */
	function parse(text, delim, maxRows) {
		var rows = [], row = [], field = '', i = 0, q = false;
		while (i < text.length && rows.length < maxRows) {
			var c = text.charAt(i);
			if (q) {
				if (c === '"' && text.charAt(i + 1) === '"') { field += '"'; i += 2; continue; }
				if (c === '"') { q = false; i++; continue; }
				field += c; i++; continue;
			}
			if (c === '"' && field === '') { q = true; i++; continue; }
			if (c === delim) { row.push(field); field = ''; i++; continue; }
			if (c === '\r') { i++; continue; }
			if (c === '\n') { row.push(field); rows.push(row); row = []; field = ''; i++; continue; }
			field += c; i++;
		}
		if ((field !== '' || row.length) && rows.length < maxRows) { row.push(field); rows.push(row); }
		return rows;
	}

	function formatOf(form, file) {
		var f = form.elements.format ? form.elements.format.value : 'auto';
		if (f !== 'auto') return f;
		var ext = (file.name.split('.').pop() || '').toLowerCase();
		if (ext === 'csv') return 'csv';
		if (ext === 'txt' || ext === 'tsv' || ext === 'tab') return 'tab';
		if (ext === 'xml') return 'xml';
		return 'csv';
	}

	function show(form) {
		var input = form.elements.source;
		var box = form.querySelector('.import-preview');
		if (!input || !box) return;
		var file = input.files && input.files[0];
		box.textContent = '';
		if (!file) { box.hidden = true; return; }
		box.hidden = false;
		var fmt = formatOf(form, file);
		if (fmt === 'xml') {
			var p = document.createElement('p');
			p.className = 'hint';
			p.textContent = form.getAttribute('data-label-xml') || '';
			box.appendChild(p);
			return;
		}
		var reader = new FileReader();
		reader.onload = function () {
			var rows = parse(String(reader.result), fmt === 'tab' ? '\t' : ',', MAX_ROWS + 1);
			box.textContent = '';
			if (!rows.length) return;

			var columns = [];
			try { columns = JSON.parse(form.getAttribute('data-columns') || '[]'); } catch (e) { /* ignore */ }
			var unknown = rows[0].filter(function (name) { return columns.indexOf(name) === -1; });
			var check = document.createElement('p');
			check.className = unknown.length ? 'message error' : 'message';
			check.textContent = unknown.length
				? (form.getAttribute('data-label-unknown') || '%s').replace('%s', unknown.join(', '))
				: (form.getAttribute('data-label-ok') || '');
			box.appendChild(check);

			var h = document.createElement('h3');
			h.textContent = form.getAttribute('data-label-preview') || '';
			box.appendChild(h);
			var wrap = document.createElement('div');
			wrap.className = 'ppa-scroll-x';
			var table = document.createElement('table');
			rows.forEach(function (r, n) {
				var tr = document.createElement('tr');
				tr.className = n ? 'data' + (n % 2 ? 1 : 2) : '';
				r.forEach(function (v) {
					var cell = document.createElement(n ? 'td' : 'th');
					if (!n) cell.className = 'data' + (columns.indexOf(v) === -1 ? ' import-unknown' : '');
					cell.textContent = v.length > 80 ? v.slice(0, 80) + '…' : v;
					tr.appendChild(cell);
				});
				table.appendChild(tr);
			});
			wrap.appendChild(table);
			box.appendChild(wrap);
		};
		reader.readAsText(file.slice(0, READ_BYTES));
	}

	document.addEventListener('change', function (e) {
		var form = e.target.form;
		if (!form || !form.classList.contains('import-form')) return;
		if (e.target.name === 'source' || e.target.name === 'format') show(form);
	});
})();

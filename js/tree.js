/*
 * Sidebar object tree.
 *
 * Reads the same XML the old xloadtree frame used (servers.php?action=tree
 * and the "src" URLs of each node), loads branches when they are opened and
 * remembers which branches are open in localStorage, keyed by the path of
 * node names, so the tree comes back the same after a reload.
 *
 *   <tree>
 *     <tree text="..." action="url" src="branch xml url" icon="img"
 *           iconaction="url" openicon="img" tooltip="..." />
 *   </tree>
 */
(function () {
	'use strict';

	var ppa = window.ppa = window.ppa || {};
	var STORE = 'ppa.tree.open';
	var MAX_REMEMBERED = 500;

	function readOpen() {
		var raw = ppa.storageGet ? ppa.storageGet(STORE) : null;
		var set = {};
		if (raw) {
			try {
				JSON.parse(raw).forEach(function (k) { set[k] = 1; });
			} catch (e) { /* ignore */ }
		}
		return set;
	}

	function Tree(container, cfg) {
		this.container = container;
		this.cfg = cfg;
		this.open = readOpen();
		this.generation = 0;
		this.filterText = '';
		this.selected = null;

		this.list = document.createElement('ul');
		this.list.className = 'ppa-tree';
		this.list.setAttribute('role', 'tree');
		this.list.setAttribute('aria-label', cfg.rootText);
		container.appendChild(this.list);

		this.empty = document.createElement('p');
		this.empty.className = 'ppa-tree-empty';
		this.empty.hidden = true;
		this.empty.textContent = cfg.noMatchText;
		container.appendChild(this.empty);

		// While filtering: a link to search the whole current database,
		// since the filter only sees branches that have been loaded.
		this.search = document.createElement('a');
		this.search.className = 'ppa-tree-search';
		this.search.hidden = true;
		container.appendChild(this.search);

		this.root = this.makeNode(null, {
			text: cfg.rootText,
			action: cfg.rootAction,
			src: cfg.src,
			icon: cfg.rootIcon
		});
		this.list.appendChild(this.root.li);
		this.root.label.setAttribute('tabindex', '0');
		this.expand(this.root);
		this.bind();
	}

	Tree.prototype.saveOpen = function () {
		var keys = Object.keys(this.open);
		if (keys.length > MAX_REMEMBERED) keys = keys.slice(keys.length - MAX_REMEMBERED);
		if (ppa.storageSet) ppa.storageSet(STORE, JSON.stringify(keys));
	};

	Tree.prototype.makeNode = function (parent, data) {
		var node = {
			parent: parent,
			data: data,
			key: parent ? parent.key + '\u0001' + data.text : 'root',
			level: parent ? parent.level + 1 : 1,
			children: null,
			expanded: false,
			loading: false
		};

		var li = document.createElement('li');
		li.setAttribute('role', 'treeitem');
		li.setAttribute('aria-level', String(node.level));
		li._node = node;

		var row = document.createElement('div');
		row.className = 'ppa-node';

		var twisty = document.createElement('span');
		twisty.className = 'ppa-twisty';
		twisty.setAttribute('aria-hidden', 'true');
		row.appendChild(twisty);

		if (data.icon) {
			var img = document.createElement('img');
			img.src = data.icon;
			img.alt = '';
			img.className = 'ppa-icon';
			if (data.iconaction) {
				var ia = document.createElement('a');
				ia.href = data.iconaction;
				ia.tabIndex = -1;
				ia.className = 'ppa-icon-link';
				ia.appendChild(img);
				row.appendChild(ia);
			} else {
				row.appendChild(img);
			}
			node.icon = img;
		}

		var label;
		if (data.action) {
			label = document.createElement('a');
			label.href = data.action;
		} else {
			label = document.createElement('span');
		}
		label.className = 'ppa-label';
		label.tabIndex = -1;
		label.textContent = data.text;
		if (data.tooltip) label.title = data.tooltip;
		row.appendChild(label);

		li.appendChild(row);

		if (data.src) {
			li.setAttribute('aria-expanded', 'false');
			var group = document.createElement('ul');
			group.setAttribute('role', 'group');
			group.hidden = true;
			li.appendChild(group);
			node.group = group;
		} else {
			li.classList.add('ppa-leaf');
		}

		node.li = li;
		node.row = row;
		node.label = label;
		return node;
	};

	Tree.prototype.setIcon = function (node) {
		if (!node.icon) return;
		var d = node.data;
		node.icon.src = (node.expanded && d.openicon) ? d.openicon : d.icon;
	};

	Tree.prototype.expand = function (node, opts) {
		opts = opts || {};
		if (!node.data.src) return Promise.resolve();
		node.expanded = true;
		node.li.setAttribute('aria-expanded', 'true');
		node.group.hidden = false;
		this.setIcon(node);
		if (!opts.restoring) {
			this.open[node.key] = 1;
			this.saveOpen();
		}
		if (node.loading && !opts.reload) return node.loadPromise;
		if (node.children === null || opts.reload) return this.load(node);
		return Promise.resolve();
	};

	Tree.prototype.collapse = function (node) {
		if (!node.data.src) return;
		node.expanded = false;
		node.li.setAttribute('aria-expanded', 'false');
		node.group.hidden = true;
		this.setIcon(node);
		delete this.open[node.key];
		this.saveOpen();
	};

	Tree.prototype.toggle = function (node) {
		if (node.expanded) this.collapse(node);
		else this.expand(node);
	};

	Tree.prototype.message = function (node, text, cls, icon) {
		var li = document.createElement('li');
		li.setAttribute('role', 'none');
		li.className = 'ppa-message ' + (cls || '');
		if (icon) {
			var img = document.createElement('img');
			img.src = icon;
			img.alt = '';
			img.className = 'ppa-icon';
			li.appendChild(img);
		}
		li.appendChild(document.createTextNode(text));
		node.group.appendChild(li);
		return li;
	};

	Tree.prototype.load = function (node) {
		var self = this;
		var gen = this.generation;
		node.loading = true;
		node.li.setAttribute('aria-busy', 'true');
		while (node.group.firstChild) node.group.removeChild(node.group.firstChild);
		this.message(node, this.cfg.loadingText, 'ppa-loading');

		return node.loadPromise = fetch(node.data.src, { credentials: 'same-origin', headers: { 'Accept': 'text/xml' } })
			.then(function (res) { return res.text(); })
			.then(function (text) {
				if (gen !== self.generation) return;
				var xml = new DOMParser().parseFromString(text, 'text/xml');
				var top = xml.documentElement;
				if (!top || top.nodeName !== 'tree' || xml.getElementsByTagName('parsererror').length) {
					throw new Error('bad tree xml');
				}
				var items = [];
				for (var c = top.firstChild; c; c = c.nextSibling) {
					if (c.nodeType === 1 && c.nodeName === 'tree') items.push(c);
				}
				self.fill(node, items);
			})
			.catch(function () {
				if (gen !== self.generation) return;
				node.children = null;
				while (node.group.firstChild) node.group.removeChild(node.group.firstChild);
				var li = self.message(node, self.cfg.errorText, 'ppa-error', self.cfg.errorIcon);
				li.title = self.cfg.errorText;
				li.addEventListener('click', function () { self.load(node); });
			})
			.then(function () {
				node.loading = false;
				node.li.removeAttribute('aria-busy');
			});
	};

	Tree.prototype.fill = function (node, items) {
		var self = this;
		while (node.group.firstChild) node.group.removeChild(node.group.firstChild);
		node.children = [];
		var pending = [];

		items.forEach(function (el) {
			var data = {
				text: el.getAttribute('text') || '',
				action: el.getAttribute('action') || '',
				src: el.getAttribute('src') || '',
				icon: el.getAttribute('icon') || '',
				iconaction: el.getAttribute('iconaction') || '',
				openicon: el.getAttribute('openicon') || '',
				tooltip: el.getAttribute('tooltip') || ''
			};
			// "No objects" placeholder rows have no link and no branch.
			if (!data.action && !data.src) {
				self.message(node, data.text, 'ppa-nodata', data.icon);
				return;
			}
			var child = self.makeNode(node, data);
			node.children.push(child);
			node.group.appendChild(child.li);
			if (self.selectedKey === child.key) self.select(child);
			if (data.src && self.open[child.key]) {
				pending.push(self.expand(child, { restoring: true }));
			} else if (data.src && self.expandWhenBranch === child.key) {
				// A server clicked before logging in has a branch now: open it.
				self.expandWhenBranch = null;
				pending.push(self.expand(child));
			}
		});

		if (this.filterText) this.applyFilter();
		return Promise.all(pending);
	};

	/** Fetch everything again, keeping open branches open. */
	Tree.prototype.reload = function () {
		this.generation++;
		this.open = readOpen();
		return this.expand(this.root, { reload: true, restoring: true });
	};

	Tree.prototype.select = function (node) {
		if (this.selected && this.selected !== node) {
			this.selected.row.classList.remove('selected');
			this.selected.li.removeAttribute('aria-selected');
		}
		this.selected = node;
		this.selectedKey = node.key;
		node.row.classList.add('selected');
		node.li.setAttribute('aria-selected', 'true');
		this.focusable(node);
	};

	// Roving tabindex: one tree item is reachable with Tab.
	Tree.prototype.focusable = function (node) {
		var prev = this.list.querySelector('.ppa-label[tabindex="0"]');
		if (prev && prev !== node.label) prev.tabIndex = -1;
		node.label.tabIndex = 0;
	};

	Tree.prototype.visibleNodes = function () {
		var out = [];
		var walk = function (node) {
			if (node.li.classList.contains('ppa-hidden')) return;
			out.push(node);
			var showKids = node.expanded || node.li.classList.contains('ppa-filter-open');
			if (showKids && node.children) node.children.forEach(walk);
		};
		walk(this.root);
		return out;
	};

	Tree.prototype.nodeFor = function (el) {
		var li = el && el.closest ? el.closest('li[role="treeitem"]') : null;
		return li && this.list.contains(li) ? li._node : null;
	};

	Tree.prototype.bind = function () {
		var self = this;

		this.list.addEventListener('click', function (e) {
			var node = self.nodeFor(e.target);
			if (!node) return;
			if (e.target.closest('.ppa-twisty')) {
				self.toggle(node);
				return;
			}
			if (e.target.closest('a')) {
				// Following a link also opens its branch.
				self.select(node);
				if (node.data.src && !node.expanded) self.expand(node);
				else if (!node.data.src) self.expandWhenBranch = node.key;
			}
		});

		this.list.addEventListener('keydown', function (e) {
			var node = self.nodeFor(e.target);
			if (!node || e.altKey || e.ctrlKey || e.metaKey) return;
			var visible = self.visibleNodes();
			var i = visible.indexOf(node);
			var go = function (n) {
				if (!n) return;
				self.focusable(n);
				n.label.focus();
			};
			var rtl = getComputedStyle(self.list).direction === 'rtl';
			var key = e.key;
			if (rtl && key === 'ArrowRight') key = 'ArrowLeft';
			else if (rtl && key === 'ArrowLeft') key = 'ArrowRight';

			switch (key) {
				case 'ArrowDown': go(visible[i + 1]); break;
				case 'ArrowUp': go(visible[i - 1]); break;
				case 'Home': go(visible[0]); break;
				case 'End': go(visible[visible.length - 1]); break;
				case 'ArrowRight':
					if (node.data.src && !node.expanded) self.expand(node);
					else if (node.children && node.children.length) go(node.children[0]);
					break;
				case 'ArrowLeft':
					if (node.expanded && node !== self.root) self.collapse(node);
					else go(node.parent);
					break;
				case 'Enter':
					if (node.label.nodeName !== 'A') {
						self.toggle(node);
						break;
					}
					return;   // the link follows itself
				default:
					return;
			}
			e.preventDefault();
		});
	};

	/* Filter: only looks at branches that have been loaded. */
	Tree.prototype.setFilter = function (text) {
		this.filterText = (text || '').trim().toLowerCase();
		this.applyFilter();
	};

	Tree.prototype.applyFilter = function () {
		var q = this.filterText;
		var any = false;
		var walk = function (node) {
			var kids = node.children || [];
			var childMatch = false;
			for (var i = 0; i < kids.length; i++) {
				if (walk(kids[i])) childMatch = true;
			}
			var self = q !== '' && node.data.text.toLowerCase().indexOf(q) !== -1;
			var show = q === '' || self || childMatch;
			node.li.classList.toggle('ppa-hidden', !show);
			node.li.classList.toggle('ppa-filter-open', q !== '' && childMatch);
			node.row.classList.toggle('ppa-match', self);
			if (self) any = true;
			return show;
		};
		// The root itself never hides.
		var kids = this.root.children || [];
		for (var i = 0; i < kids.length; i++) walk(kids[i]);
		this.root.li.classList.toggle('ppa-filter-open', q !== '');
		this.list.classList.toggle('ppa-filtering', q !== '');
		this.empty.hidden = q === '' || any;
		this.updateSearch();
	};

	/** The database of the page being shown, from its address. */
	function currentDatabase() {
		var p = new URLSearchParams(location.search);
		return p.get('server') && p.get('database') ? { server: p.get('server'), database: p.get('database') } : null;
	}

	Tree.prototype.updateSearch = function () {
		var q = (document.getElementById('ppa-tree-filter') || {}).value || '';
		q = q.trim();
		var db = currentDatabase();
		if (q === '' || !db || !this.cfg.searchText) {
			this.search.hidden = true;
			return;
		}
		var u = new URL('database.php', location.href);
		u.search = new URLSearchParams({ server: db.server, database: db.database, subject: 'database', action: 'find', term: q }).toString();
		this.search.href = u.href;
		this.search.textContent = this.cfg.searchText.replace('%1', q).replace('%2', db.database);
		this.search.hidden = false;
	};

	/* ---------------------------------------------------------------- */
	/* Reveal: open the branches down to the object the page shows       */
	/* ---------------------------------------------------------------- */

	// Where the objects of a kind are listed, for picking the right folder.
	var FOLDERS = {
		schema: 'schemas.php', table: 'tables.php', view: 'views.php', matview: 'materializedviews.php',
		sequence: 'sequences.php', function: 'functions.php', domain: 'domains.php', type: 'types.php',
		aggregate: 'aggregates.php', operator: 'operators.php', fulltext: 'fulltext.php'
	};
	var LEVELS = ['server', 'database', 'schema'];

	function paramsOf(href) {
		if (!href) return null;
		try {
			var u = new URL(href, location.href);
			return { file: u.pathname.substring(u.pathname.lastIndexOf('/') + 1), p: u.searchParams };
		} catch (e) { return null; }
	}

	/** What the page shows, as the keys the tree uses in its URLs. */
	function pageTarget() {
		var p = new URLSearchParams(location.search);
		if (!p.get('server')) return null;
		var keys = [];
		LEVELS.forEach(function (k) { if (p.get(k)) keys.push([k, p.get(k)]); });
		var subject = p.get('subject');
		if (subject && LEVELS.indexOf(subject) === -1 && p.get(subject) && FOLDERS[subject]) keys.push([subject, p.get(subject)]);
		return keys;
	}

	Tree.prototype.reveal = function () {
		var target = pageTarget();
		var token = this.revealToken = (this.revealToken || 0) + 1;
		if (!target) return Promise.resolve();
		var self = this;

		// A node fits when none of its URL parameters contradicts the target;
		// "depth" is how many target keys, in order, it carries.
		function fit(node) {
			var a = paramsOf(node.data.src) || paramsOf(node.data.action);
			var b = paramsOf(node.data.action);
			if (!a) return null;
			var depth = 0;
			for (var i = 0; i < target.length; i++) {
				var k = target[i][0];
				var v = a.p.get(k) !== null ? a.p.get(k) : (b ? b.p.get(k) : null);
				if (v === null) break;
				if (v !== target[i][1]) return null;
				depth = i + 1;
			}
			// A key of another kind (e.g. table= when looking for a view) is a miss.
			for (var j = depth; j < target.length; j++) {
				if (a.p.get(target[j][0]) !== null && a.p.get(target[j][0]) !== target[j][1]) return null;
			}
			return { depth: depth, file: a.file };
		}

		function step(node, depth, guard) {
			if (token !== self.revealToken || guard > 10) return;
			if (depth >= target.length) {
				self.select(node);
				var r = node.row.getBoundingClientRect(), c = self.container.getBoundingClientRect();
				if (r.top < c.top || r.bottom > c.bottom) node.row.scrollIntoView({ block: 'nearest' });
				return;
			}
			var ready = node.expanded && node.children ? Promise.resolve() : self.expand(node, { restoring: true });
			return ready.then(function () {
				if (token !== self.revealToken || !node.children) return;
				var best = null, folder = null;
				var want = target[depth][0];
				node.children.forEach(function (c) {
					var f = fit(c);
					if (!f) return;
					if (f.depth > depth && (!best || f.depth > best.f.depth)) best = { n: c, f: f };
					else if (f.depth === depth && c.data.src && f.file === FOLDERS[want] && !folder) folder = c;
				});
				if (best) return step(best.n, best.f.depth, guard + 1);
				if (folder) return step(folder, depth, guard + 1);
			});
		}
		return Promise.resolve(step(this.root, 0, 0));
	};

	Tree.prototype.firstMatch = function () {
		var nodes = this.visibleNodes();
		for (var i = 0; i < nodes.length; i++) {
			if (nodes[i].row.classList.contains('ppa-match') && nodes[i].label.nodeName === 'A') return nodes[i];
		}
		return null;
	};

	function init() {
		var el = document.getElementById('ppa-tree');
		if (!el || ppa.tree) return;
		var cfg;
		try { cfg = JSON.parse(el.getAttribute('data-config')); } catch (e) { return; }
		var tree = ppa.tree = new Tree(el, cfg);
		tree.reveal();

		var refresh = document.getElementById('ppa-tree-refresh');
		if (refresh) refresh.addEventListener('click', function () { tree.reload(); });

		var filter = document.getElementById('ppa-tree-filter');
		if (filter) {
			filter.addEventListener('input', function () { tree.setFilter(filter.value); });
			filter.addEventListener('keydown', function (e) {
				if (e.key === 'Enter') {
					e.preventDefault();
					var n = tree.firstMatch();
					if (n) {
						tree.select(n);
						n.label.click();
					} else if (!tree.search.hidden) {
						tree.search.click();
					}
				} else if (e.key === 'Escape') {
					if (filter.value !== '') {
						e.stopPropagation();
						filter.value = '';
						tree.setFilter('');
					}
				} else if (e.key === 'ArrowDown') {
					e.preventDefault();
					var m = tree.firstMatch() || tree.visibleNodes()[0];
					if (m) {
						tree.focusable(m);
						m.label.focus();
					}
				}
			});
		}
	}

	document.addEventListener('DOMContentLoaded', init);

	// Follow the page: open the tree down to what it shows.
	document.addEventListener('ppa:load', function (e) {
		if (e.detail && e.detail.dialog) return;
		if (!ppa.tree) return;
		ppa.tree.reveal();
		ppa.tree.updateSearch();
	});
})();

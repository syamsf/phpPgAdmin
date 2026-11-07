var predefined_lengths = null;
var sizesLength = false;

function checkLengths(sValue,idx) {
        if(predefined_lengths) {
                if(sizesLength==false) {
                        sizesLength = predefined_lengths.length;
                }
                for(var i=0;i<sizesLength;i++) {
                        if(sValue.toString().toUpperCase()==predefined_lengths[i].toString().toUpperCase()) {
                                document.getElementById("lengths"+idx).value='';
                                document.getElementById("lengths"+idx).disabled='on';
                                return;
                        }
                }
                document.getElementById("lengths"+idx).disabled='';
        }
}

/* Create table: "Add column" copies the last row with the next index. */
(function () {
	if (window.ppaCreateColumns) return;
	window.ppaCreateColumns = true;
	document.addEventListener('click', function (e) {
		if (!e.target.closest || !e.target.closest('#create-add-column')) return;
		var table = document.getElementById('create-columns');
		var count = document.getElementById('create-fields');
		if (!table || !count) return;
		var rows = table.querySelectorAll('tr');
		var last = rows[rows.length - 1];
		var n = parseInt(count.value, 10) || (rows.length - 1);
		var old = n - 1;
		var row = last.cloneNode(true);
		row.querySelectorAll('script').forEach(function (s) { s.parentNode.removeChild(s); });
		row.querySelectorAll('[name]').forEach(function (el) {
			el.name = el.name.replace('[' + old + ']', '[' + n + ']');
			if (el.type === 'checkbox') el.checked = false;
			else if (el.nodeName === 'INPUT') { el.value = ''; el.disabled = false; }
		});
		var type = row.querySelector('select[id^=types]');
		if (type) {
			type.id = 'types' + n;
			type.value = 'text';
			type.setAttribute('onchange', 'checkLengths(this.options[this.selectedIndex].value,' + n + ');');
		}
		var len = row.querySelector('input[id^=lengths]');
		if (len) len.id = 'lengths' + n;
		row.querySelectorAll('select[name^=array]').forEach(function (s) { s.value = ''; });
		var num = row.querySelector('td');
		if (num) num.textContent = (n + 1) + '.\u00a0';
		last.parentNode.appendChild(row);
		count.value = String(n + 1);
		if (type) checkLengths(type.value, n);
		var name = row.querySelector('input[name^=field]');
		if (name) name.focus();
	});
})();

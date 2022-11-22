(function() {
	var viewsource = [];
	var copycode = [];
	if(document.getElementsByClassName) {
		viewsource = document.getElementsByClassName('viewsource');
		copycode = document.getElementsByClassName('copycode');
	} else {
		var emlist = document.getElementsByTagName('em');
		for(var i=0;i<emlist.length;i++) {
			if(emlist[i].className == 'viewsource') {
				viewsource.push(emlist[i]);
			} else if(emlist[i].className == 'copycode') {
				copycode.push(emlist[i]);
			}
		}
	}
	function mw_code_toolbar_addevent(objs, eventtype) {
		for(var i=0; i<objs.length; i++) {
			if(objs[i].id != undefined) {
				objs[i].setAttribute('num', i);
				objs[i].onclick = function() {
					var highlighters = SyntaxHighlighter.vars.highlighters;
					var k = 0;
					var num = this.getAttribute('num');
					for(var i in highlighters) {
						if(k == num) {
							if(eventtype == 'viewcode') {
								mw_viewcode_execute(highlighters[i]);
							} else if(eventtype == 'copycode') {
								mw_copycode_execute(highlighters[i]);
							}
							break;
						}
						k++;
					}
					return false;
				}
			}
		}
	}
	if(viewsource) {
		mw_code_toolbar_addevent(viewsource, 'viewcode');
	}
	if(copycode) {
		mw_code_toolbar_addevent(copycode, 'copycode');
	}
	function mw_viewcode_execute(highlighter) {
		var code = mw_get_code(highlighter);
		code = mw_fixinputstring(code).replace(/</g, '&lt;');
		var wnd = mw_popup('', '_blank', 750, 400, 'location=0, resizable=1, menubar=0, scrollbars=1');
		code = mw_unindent(code);
		wnd.document.write('<pre>' + code + '</pre>');
		wnd.document.close();
	}
	function mw_copycode_execute(highlighter) {
		var code = mw_get_code(highlighter);
		code = mw_fixinputstring(code)
			.replace(/&lt;/g, '<')
			.replace(/&gt;/g, '>')
			.replace(/&amp;/g, '&')
			;
		code = mw_unindent(code);
		setCopy(code, mw_lang_toolbar['copyed']);
	}
	function mw_fixinputstring(str) {
		var br = /<br\s*\/>|<br\s*>|&lt;br\s*\/?&gt;/gi;
		if(SyntaxHighlighter.config.bloggerMode == true) {
			str = str.replace(br, '\n');
		}
		if(SyntaxHighlighter.config.stripBrs == true) {
			str = str.replace(br, '');
		}
		return str;
	}
	function mw_popup(url, name, width, height, options) {
		var x = (screen.width - width) / 2,
			y = (screen.height - height) / 2
			;
		options +=	', left=' + x +
					', top=' + y +
					', width=' + width +
					', height=' + height
			;
		options = options.replace(/^,/, '');
		var win = window.open(url, name, options);
		win.focus();
		return win;
	}
	function mw_unindent(str) {
		var lines = mw_fixinputstring(str).split('\n'),
			indents = new Array(),
			regex = /^\s*/,
			min = 1000
			;
		for(var i = 0; i < lines.length && min > 0; i++) {
			var line = lines[i];
			if(mw_trim(line).length == 0) {
				continue;
			}
			var matches = regex.exec(line);
			if(matches == null) {
				return str;
			}
			min = Math.min(matches[0].length, min);
		}
		if(min > 0) {
			for(var i = 0; i < lines.length; i++) {
				lines[i] = lines[i].substr(min);
			}
		}
		return lines.join('\n');
	}
	function mw_trim(str) {
		return str.replace(/^\s+|\s+$/g, '');
	}
	function mw_get_code(highlighter) {
		if (mw_libversion == '3.0.90') {
			var container = mw_findelement($('highlighter_' + highlighter.id), '.container');
			var lines = container.childNodes;
			var code = [];
			for(var i=0; i<lines.length; i++) {
				code.push(lines[i].innerText || lines[i].textContent);
			}
			code = code.join('\r');
			return code;
		} else if(mw_libversion == '2.1.382') {
			return highlighter.originalCode;
		}
	}
	function mw_findelement(target, search, reverse) {
		if(target == null)
			return null;
		var nodes = reverse != true ? target.childNodes : [ target.parentNode ],
			propertyToFind	= { '#' : 'id', '.' : 'className' }[search.substr(0, 1)] || 'nodeName',
			expectedValue,
			found
			;
		expectedValue = propertyToFind != 'nodeName'
			? search.substr(1)
			: search.toUpperCase()
			;
		if((target[propertyToFind] || '').indexOf(expectedValue) != -1)
			return target;
		for(var i = 0; nodes && i < nodes.length && found == null; i++)
			found = mw_findelement(nodes[i], search, reverse);
		return found;
	}
})();

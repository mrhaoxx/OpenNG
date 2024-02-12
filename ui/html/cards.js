function version_card(parent) {
    const card = new Card(parent, ['version']);
    card.addTitle('Version');
    card.addText('version: ' + doc.getIn(['version']), { fontWeight: 'regular', fontSize: '16px' });

    card.status = doc.getIn(['version']) === 4;
    card.updateStatus();
}

function logger_card(parent) {
    var card = new Card(parent, ['Logger']);

    card.addTitle('Logger');
    card.startTable();
    card.addCheckbox('Enable SSE', ['EnableSSE']);
    card.addCheckbox('Disable Console', ['DisableConsole']);
    card.addInput('UDP Logger', 'Enter UDP Server Address', ['UdpLogger', 'Address']);
    card.addInput('File Logger', 'Enter File Path', ['File']);
    card.addValidSubpath('UdpLogger');

    card.checkUnusedSubpath();
    card.updateStatus();

}

function tls_card(parent) {
    var card = new Card(parent, ['TLS']);

    card.addTitle('TLS');
    card.startTable();
    card.addInput('Certificate', 'Enter Certificate Path', ['Certificates']);
    card.addInput('Key', 'Enter Key Path', ['Key']);
    card.addValidSubpath('Certificate');

    card.checkUnusedSubpath();
    card.updateStatus();
}

class Card {
    constructor(parent, path) {
        this.path = path;
        this.status = true;
        this.usedsubpath = {};
        this.arraymap = {};
        const card = document.createElement('div');

        card.style.padding = '20px';
        card.style.position = 'relative';
        card.onclick = function () {
            focus(path);
        }
        this.card = card;

        parent.appendChild(card);
    }
    setSubcard() {
        this.card.style.padding = '0px';
        this.card.style.paddingLeft = '10px';
    }
    updateStatus() {
        var statusFlag = document.createElement('div');
        statusFlag.textContent = this.status ? '✅' : '❌';

        statusFlag.style.top = '30px';
        statusFlag.style.right = '20px';

        statusFlag.style.height = '30px';
        statusFlag.style.width = '30px';
        statusFlag.style.position = 'absolute';
        statusFlag.style.backgroundColor = '#ccc';
        statusFlag.style.borderRadius = '50%';
        statusFlag.style.display = 'flex';
        statusFlag.style.alignItems = 'center';
        statusFlag.style.justifyContent = 'center';

        this.card.appendChild(statusFlag);
    }

    addTitle(text) {
        var title = document.createElement('h2');
        title.textContent = text;
        title.style.margin = '3px';
        title.style.paddingBottom = '5px';
        title.style.marginBottom = '20px';

        this.card.appendChild(title);
    }

    addText(txt, style = {}) {
        var text = document.createElement('p');
        text.appendChild(document.createTextNode(txt));
        text.style.margin = '3px';

        Object.keys(style).forEach(key => {
            text.style[key] = style[key];
        });

        this.card.appendChild(text);
    }

    startTable() {
        var table = document.createElement('table');
        table.style.width = '100%';
        this.table = table;
        this.card.appendChild(table);
        return table;
    }

    addCheckbox(label, subpath) {

        var rpath = this.path.concat(subpath);

        var tr = document.createElement('tr');
        var tdLabel = document.createElement('td');
        tdLabel.textContent = label;
        var tdCheckbox = document.createElement('td');
        tdCheckbox.style.textAlign = 'right';
        var checkbox = document.createElement('input');
        checkbox.type = 'checkbox';
        var spec = doc.getIn(rpath);
        checkbox.checked = spec === true;

        checkbox.onchange = function () {
            setdoc(rpath, this.checked);
        }

        if (spec !== undefined && typeof spec !== 'boolean') {
            this.status = false;
        }

        tdCheckbox.appendChild(checkbox);
        tr.appendChild(tdLabel);
        tr.appendChild(tdCheckbox);
        this.table.appendChild(tr);

        this.usedsubpath[subpath] = true;
    }

    forEachArray(label, subpath, callback) {
        var rpath = this.path.concat(subpath);
        var rvec = doc.getIn(rpath);
        var i = 0;
        this.startTable();

        var tr = document.createElement('tr');
        var tdLabel = document.createElement('td');
        tdLabel.textContent = label;
        tr.appendChild(tdLabel);
        this.table.appendChild(tr);

        if (typeof rvec === 'object') {
            var rvalue = doc.getIn(rpath).items;
            var curlength = rvalue.length;
            for (; i < curlength; i++) {
                callback(rpath, i, rvalue[i]);
            }
        }

        this.usedsubpath[subpath] = true;
    }

    addInput(label, placeholder, subpath, oninput) {
        var rpath = this.path.concat(subpath);

        var tr = document.createElement('tr');
        var tdLabel = document.createElement('td');
        tdLabel.textContent = label;
        var tdInput = document.createElement('td');
        var input = document.createElement('input');
        input.type = 'text';
        input.placeholder = placeholder;
        var rvalue = doc.getIn(rpath);
        input.value = rvalue === undefined ? '' : rvalue;
        if (rvalue !== undefined && typeof rvalue !== 'string') {
            this.status = false;
        }

        if (oninput) {
            input.oninput = oninput;
        } else {
            input.oninput = function () {
                if (this.value === '') {
                    deldoc(rpath);
                } else {
                    setdoc(rpath, this.value);
                }
            }
        }
        input.style.boxSizing = 'border-box';
        input.style.width = '100%';
        tdInput.appendChild(input);
        tr.appendChild(tdLabel);
        tr.appendChild(tdInput);
        this.table.appendChild(tr);

        this.usedsubpath[subpath] = true;
    }

    addStringArray(label, placeholder, subpath) {
        var rpath = this.path.concat(subpath);
        var rvec = doc.getIn(rpath)
        var i = 0
        this.startTable()

        var tr = document.createElement('tr');
        var tdLabel = document.createElement('td');
        tdLabel.textContent = label;
        tr.appendChild(tdLabel);
        this.table.appendChild(tr);

        if (typeof rvec === 'object') {

            var rvalue = doc.getIn(rpath).items;
            var curlength = rvalue.length
            for (; i < curlength; i++) {
                const tr = document.createElement('tr');
                const tdLabel = document.createElement('td');
                const tdInput = document.createElement('td');

                const input = document.createElement('input');
                input.type = 'text';
                input.placeholder = placeholder;
                input.value = rvalue[i];

                if (rvalue !== undefined && typeof rvalue !== 'string') {
                    this.status = false;
                }
                var table = this.table
                input.oninput = function () {
                    if (this.value != "") {
                        setdoc(rpath.concat(tr.rowIndex - 1), this.value)
                    } else {
                        deldoc(rpath.concat(tr.rowIndex - 1))
                        var i = tr.rowIndex;
                        table.removeChild(tr)
                        table.childNodes[i].lastChild.lastChild.focus();
                    }
                }
                input.style.boxSizing = 'border-box';
                input.style.width = '100%';
                tdInput.appendChild(input);
                tr.appendChild(tdLabel);
                tr.appendChild(tdInput);
                this.table.appendChild(tr);
            }

        }


        this.createPlaceholderInput(this.table, placeholder, rpath, this)

        this.usedsubpath[subpath] = true;


    }
    createPlaceholderInput(parent, placeholder, rpath, _this){
        var tr = document.createElement('tr');
        var tdLabel = document.createElement('td');
        var tdInput = document.createElement('td');
        var input = document.createElement('input');

        input.type = 'text';
        input.placeholder = placeholder;
        input.style.boxSizing = 'border-box';
        input.style.border = "1px dashed #000";
        input.style.width = '100%';
        input.oninput = function(){
            setdoc(rpath.concat(tr.rowIndex - 1), this.value)
            this.oninput= function () {
                if (this.value != "") {
                    setdoc(rpath.concat(tr.rowIndex - 1), this.value)
                } else {
                    deldoc(rpath.concat(tr.rowIndex - 1))
                    var i = tr.rowIndex;
                    parent.removeChild(tr)
                    parent.childNodes[i].lastChild.lastChild.focus();
                }
            };
            this.style.border = ""
            _this.createPlaceholderInput(parent, placeholder, rpath, _this)
        }
        
        tdInput.appendChild(input);
        tr.appendChild(tdLabel);
        tr.appendChild(tdInput);

        parent.appendChild(tr)
    }

    addValidSubpath(subpath) {
        this.usedsubpath[subpath] = true;
    }

    checkUnusedSubpath() {
        Object.keys(doc.getIn(this.path).toJSON()).forEach(key => {
            if (this.usedsubpath[key] === undefined) {
                this.status = false;
            }
        });
    }

}


function setdoc(path, value) {
    setting = true

    doc.setIn(path, value);
    var currentPosition = editor.getCursorPosition();
    editor.setValue(doc.toString())

    editor.moveCursorToPosition(currentPosition);
    editor.session.selection.clearSelection();

    setting = false
}

function deldoc(path) {
    setting = true

    doc.deleteIn(path);
    var currentPosition = editor.getCursorPosition();
    editor.setValue(doc.toString())

    editor.moveCursorToPosition(currentPosition);
    editor.session.selection.clearSelection();

    setting = false

}
function focus(path) {
    var docl = editor.session.getDocument();
    var position = docl.indexToPosition(doc.getIn(path, true).range[0], 0);

    editor.moveCursorToPosition(position);
    editor.session.selection.clearSelection();
    //focus on the editor
}

var editor;
var doc;

var setting = false;
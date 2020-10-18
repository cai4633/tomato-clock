module.exports = (function() {
var __MODS__ = {};
var __DEFINE__ = function(modId, func, req) { var m = { exports: {}, _tempexports: {} }; __MODS__[modId] = { status: 0, func: func, req: req, m: m }; };
var __REQUIRE__ = function(modId, source) { if(!__MODS__[modId]) return require(source); if(!__MODS__[modId].status) { var m = __MODS__[modId].m; m._exports = m._tempexports; var desp = Object.getOwnPropertyDescriptor(m, "exports"); if (desp && desp.configurable) Object.defineProperty(m, "exports", { set: function (val) { if(typeof val === "object" && val !== m._exports) { m._exports.__proto__ = val.__proto__; Object.keys(val).forEach(function (k) { m._exports[k] = val[k]; }); } m._tempexports = val }, get: function () { return m._tempexports; } }); __MODS__[modId].status = 1; __MODS__[modId].func(__MODS__[modId].req, m, m.exports); } return __MODS__[modId].m.exports; };
var __REQUIRE_WILDCARD__ = function(obj) { if(obj && obj.__esModule) { return obj; } else { var newObj = {}; if(obj != null) { for(var k in obj) { if (Object.prototype.hasOwnProperty.call(obj, k)) newObj[k] = obj[k]; } } newObj.default = obj; return newObj; } };
var __REQUIRE_DEFAULT__ = function(obj) { return obj && obj.__esModule ? obj.default : obj; };
__DEFINE__(1603008213925, function(require, module, exports) {
/*
 Copyright 2013 Daniel Wirtz <dcode@dcode.io>

 Licensed under the Apache License, Version 2.0 (the "License");
 you may not use this file except in compliance with the License.
 You may obtain a copy of the License at

 http://www.apache.org/licenses/LICENSE-2.0

 Unless required by applicable law or agreed to in writing, software
 distributed under the License is distributed on an "AS IS" BASIS,
 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 See the License for the specific language governing permissions and
 limitations under the License.
 */

var util = require("util"),
    path = require("path"),
    colour = require("colour");

// Default alphabet
var alphabet = require(path.join(__dirname, "alphabet", "straight.json"));

module.exports = function(appName) {
    ascli.appName = appName;
    return ascli;
};

module.exports.app = module.exports; // For backward compatibility

/**
 * Builds a banner.
 * @param {string=} title App name
 * @param {string=} appendix Appendix, e.g. version
 * @returns {string}
 */
function ascli(title, appendix) {
    title = title || ascli.appName;
    appendix = appendix || "";
    var lines = ["", "", ""], c, a, j, ac = "";
    for (var i=0; i<title.length; i++) {
        c = title.charAt(i);
        if (c == '\x1B') {
            while ((c=title.charAt(i)) != 'm') {
                ac += c;
                i++;
            }
            ac += c;
        } else if ((a=alphabet[c])||(a=alphabet[c.toLowerCase()]))
            for (j=0; j<3; j++)
                lines[j] += ac+a[j];
    }
    for (i=0; i<lines.length; i++) lines[i] = lines[i]+"\x1B[0m";
    lines[1] += " "+appendix;
    if (lines[lines.length-1].strip.trim().length == 0) {
        lines.pop();
    }
    return '\n'+lines.join('\n')+'\n';
}

// Indent by one
function indent1() {
    this.write(" "+util.format.apply(null, arguments).replace(/\n/g, "\n ")+"\n");
}
ascli.log = indent1.bind(process.stdout);
ascli.info = indent1.bind(process.stdout);
ascli.warn = indent1.bind(process.stderr);
ascli.error = indent1.bind(process.stderr);

/**
 * App name.
 * @type {string}
 */
ascli.appName = "app";

/**
 * Prints a banner to console.
 * @param {string=} title Title in dojo alphabet
 * @param {string=} appendix Title appendix
 * @returns {Function} ascli
 */
ascli.banner = function(title, appendix) {
    console.log(ascli(title, appendix));
    return ascli;
};

/**
 * Uses another alphabet.
 * @param {string|Object.<string,Array.<string>} alpha File name or alphabet to use
 * @returns {Function} ascli
 */
ascli.use = function(alpha) {
    if (typeof alpha === 'string')
        alphabet = require(alpha);
    else
        alphabet = alpha;
    return ascli;
};

/**
 * Prints a final success message.
 * @param {string} msg Message text
 * @param {number=} code Exit code, defaults not to send it explicitly
 */
ascli.ok = function(msg, code) {
    process.stderr.write('\n '+ascli.appName.green.bold+' OK'.white.bold+(msg ? ' '+msg : '')+'\n');
    if (typeof code !== 'undefined')
        process.exit(code);
};

/**
 * Prints a final failure message.
 * @param {string} msg Message text
 * @param {number=} code Exit code, defaults to not send it explicitly
 */
ascli.fail = function(msg, code) {
    process.stderr.write('\n '+ascli.appName.red.bold+' ERROR'.white.bold+(msg ? ' '+msg : '')+'\n');
    if (typeof code !== 'undefined')
        process.exit(code);
};

/**
 * opt.js
 * @param {Array.<string>=} argv
 * @returns {{node: string, script: string, argv: Array.<string>, opt: Object.<string,boolean|string>}}
 */
ascli.optjs = require("optjs");

// Pre-run it
var opt = ascli.optjs();
ascli.node = opt.node;
ascli.script = opt.script;
ascli.argv = opt.argv;
ascli.opt = opt.opt;

// Expose colour.js
ascli.colour = ascli.colors = colour;

}, function(modId) {var map = {}; return __REQUIRE__(map[modId], modId); })
return __REQUIRE__(1603008213925);
})()
//# sourceMappingURL=index.js.map
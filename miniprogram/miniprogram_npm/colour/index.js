module.exports = (function() {
var __MODS__ = {};
var __DEFINE__ = function(modId, func, req) { var m = { exports: {}, _tempexports: {} }; __MODS__[modId] = { status: 0, func: func, req: req, m: m }; };
var __REQUIRE__ = function(modId, source) { if(!__MODS__[modId]) return require(source); if(!__MODS__[modId].status) { var m = __MODS__[modId].m; m._exports = m._tempexports; var desp = Object.getOwnPropertyDescriptor(m, "exports"); if (desp && desp.configurable) Object.defineProperty(m, "exports", { set: function (val) { if(typeof val === "object" && val !== m._exports) { m._exports.__proto__ = val.__proto__; Object.keys(val).forEach(function (k) { m._exports[k] = val[k]; }); } m._tempexports = val }, get: function () { return m._tempexports; } }); __MODS__[modId].status = 1; __MODS__[modId].func(__MODS__[modId].req, m, m.exports); } return __MODS__[modId].m.exports; };
var __REQUIRE_WILDCARD__ = function(obj) { if(obj && obj.__esModule) { return obj; } else { var newObj = {}; if(obj != null) { for(var k in obj) { if (Object.prototype.hasOwnProperty.call(obj, k)) newObj[k] = obj[k]; } } newObj.default = obj; return newObj; } };
var __REQUIRE_DEFAULT__ = function(obj) { return obj && obj.__esModule ? obj.default : obj; };
__DEFINE__(1602998375483, function(require, module, exports) {
/*
 colour.js (c) 2013 Daniel Wirtz <dcode@dcode.io>
 Released under the MIT-License
 see: https://github.com/dcodeIO/colour.js for details
*/
(function(g){function d(a,b){c[a]=function(a){return b.apply(a)};try{String.prototype.__defineGetter__(a,b),e[a]=b}catch(d){}}function m(a,b){return"console"==c.mode?h[b][0]+a+h[b][1]:"browser"==c.mode?k[b][0]+a+k[b][1]:"browser-css"==c.mode?r[b][0]+a+k[b][1]:a+""}function l(a){Object.keys(a).forEach(function(b){0<=s.indexOf(b)||("string"==typeof a[b]&&(a[b]=a[b].split(" ")),d(b,function(){for(var d=this,e=0;e<a[b].length;e++)d=c[a[b][e]](d);return d}))})}function n(a){return function(){return void 0==
this?"":String.prototype.split.apply(this,[""]).map(a).join("")}}function p(){return this.replace(/\x1B\[\d+m/g,"").replace(/<\/?(?:span|u|i|u|del)\b[^>]*>/g,"")}var c={mode:"console"};c.headless="undefined"===typeof g.window;c.themes={};var h={bold:["\u001b[1m","\u001b[22m"],italic:["\u001b[3m","\u001b[23m"],underline:["\u001b[4m","\u001b[24m"],inverse:["\u001b[7m","\u001b[27m"],strikethrough:["\u001b[9m","\u001b[29m"],white:["\u001b[37m","\u001b[39m"],gray:["\u001b[90m","\u001b[39m"],grey:["\u001b[90m",
"\u001b[39m"],black:["\u001b[30m","\u001b[39m"],blue:["\u001b[34m","\u001b[39m"],cyan:["\u001b[36m","\u001b[39m"],green:["\u001b[32m","\u001b[39m"],magenta:["\u001b[35m","\u001b[39m"],red:["\u001b[31m","\u001b[39m"],yellow:["\u001b[33m","\u001b[39m"]},k={bold:["<b>","</b>"],italic:["<i>","</i>"],underline:["<u>","</u>"],inverse:['<span style="background-color:black;color:white;">',"</span>"],strikethrough:["<del>","</del>"],white:['<span style="color:white;">',"</span>"],gray:['<span style="color:gray;">',
"</span>"],grey:['<span style="color:grey;">',"</span>"],black:['<span style="color:black;">',"</span>"],blue:['<span style="color:blue;">',"</span>"],cyan:['<span style="color:cyan;">',"</span>"],green:['<span style="color:green;">',"</span>"],magenta:['<span style="color:magenta;">',"</span>"],red:['<span style="color:red;">',"</span>"],yellow:['<span style="color:yellow;">',"</span>"]},r={bold:['<span class="ansi-escape ansi-escape-bold">',"</span>"],italic:['<span class="ansi-escape ansi-escape-italic">',
"</span>"],underline:['<span class="ansi-escape ansi-escape-underline">',"</span>"],inverse:['<span class="ansi-escape ansi-escape-inverse">',"</span>"],strikethrough:['<span class="ansi-escape ansi-escape-strikethrough">',"</span>"],white:['<span class="ansi-escape ansi-escape-white">',"</span>"],gray:['<span class="ansi-escape ansi-escape-gray">',"</span>"],grey:['<span class="ansi-escape ansi-escape-grey">',"</span>"],black:['<span class="ansi-escape ansi-escape-black">',"</span>"],blue:['<span class="ansi-escape ansi-escape-blue">',
"</span>"],cyan:['<span class="ansi-escape ansi-escape-cyan">',"</span>"],green:['<span class="ansi-escape ansi-escape-green">',"</span>"],magenta:['<span class="ansi-escape ansi-escape-magenta">',"</span>"],red:['<span class="ansi-escape ansi-escape-red">',"</span>"],yellow:['<span class="ansi-escape ansi-escape-yellow">',"</span>"]},e={},f=!0;c.uninstall=function(){return f?(Object.keys(e).forEach(function(a){try{String.prototype.__defineGetter__(a,null)}catch(b){delete String.prototype[a]}}),f=
!1,!0):!1};c.install=function(){return!f?(Object.keys(e).forEach(function(a){String.prototype.__defineGetter__(a,e[a])}),f=!0):!1};var q=["red","yellow","green","blue","magenta"],s="__defineGetter__ __defineSetter__ __lookupGetter__ __lookupSetter__ charAt constructor hasOwnProperty isPrototypeOf propertyIsEnumerable toLocaleString toString valueOf charCodeAt indexOf lastIndexof length localeCompare match replace search slice split substring toLocaleLowerCase toLocaleUpperCase toLowerCase toUpperCase trim trimLeft trimRight".split(" ");
c.setTheme=function(a){if("string"===typeof a){if("undefined"!=typeof c.themes[a])return l(c.themes[a]),c.themes[a];try{return c.themes[a]=require(a),l(c.themes[a]),c.themes[a]}catch(b){return b}}else l(a)};c.addSequencer=function(a,b){d(a,n(b))};Object.keys(h).forEach(function(a){d(a,function(){return m(this,a)})});c.addSequencer("rainbow",function(a,b){return" "===a?a:m(a,q[b++%q.length])});c.addSequencer("zebra",n(function(a,b){return 0===b%2?a:a.inverse}));d("strip",p);d("stripColors",p);"undefined"!==
typeof module&&module.exports?module.exports=c:"undefined"!==typeof define&&define.amd?(define("colour",function(){return c}),define("colors",function(){return c})):(c.mode="browser",g.colour=g.colors=c)})(this);

}, function(modId) {var map = {}; return __REQUIRE__(map[modId], modId); })
return __REQUIRE__(1602998375483);
})()
//# sourceMappingURL=index.js.map
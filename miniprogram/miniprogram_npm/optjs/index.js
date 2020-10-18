module.exports = (function() {
var __MODS__ = {};
var __DEFINE__ = function(modId, func, req) { var m = { exports: {}, _tempexports: {} }; __MODS__[modId] = { status: 0, func: func, req: req, m: m }; };
var __REQUIRE__ = function(modId, source) { if(!__MODS__[modId]) return require(source); if(!__MODS__[modId].status) { var m = __MODS__[modId].m; m._exports = m._tempexports; var desp = Object.getOwnPropertyDescriptor(m, "exports"); if (desp && desp.configurable) Object.defineProperty(m, "exports", { set: function (val) { if(typeof val === "object" && val !== m._exports) { m._exports.__proto__ = val.__proto__; Object.keys(val).forEach(function (k) { m._exports[k] = val[k]; }); } m._tempexports = val }, get: function () { return m._tempexports; } }); __MODS__[modId].status = 1; __MODS__[modId].func(__MODS__[modId].req, m, m.exports); } return __MODS__[modId].m.exports; };
var __REQUIRE_WILDCARD__ = function(obj) { if(obj && obj.__esModule) { return obj; } else { var newObj = {}; if(obj != null) { for(var k in obj) { if (Object.prototype.hasOwnProperty.call(obj, k)) newObj[k] = obj[k]; } } newObj.default = obj; return newObj; } };
var __REQUIRE_DEFAULT__ = function(obj) { return obj && obj.__esModule ? obj.default : obj; };
__DEFINE__(1603008214387, function(require, module, exports) {
module.exports = (function() {
    function opt(argv) {
        var opt={},arg,p;argv=Array.prototype.slice.call(argv||process.argv);for(var i=2;i<argv.length;i++)if(argv[i].charAt(0)=='-')
        ((p=(arg=(""+argv.splice(i--,1)).replace(/^[\-]+/,'')).indexOf("="))>0?opt[arg.substring(0,p)]=arg.substring(p+1):opt[arg]=true);
        return {'node':argv[0],'script':argv[1],'argv':argv.slice(2),'opt':opt};
    }
    return opt.opt = opt;
})();

}, function(modId) {var map = {}; return __REQUIRE__(map[modId], modId); })
return __REQUIRE__(1603008214387);
})()
//# sourceMappingURL=index.js.map
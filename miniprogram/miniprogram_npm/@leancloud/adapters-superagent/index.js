module.exports = (function() {
var __MODS__ = {};
var __DEFINE__ = function(modId, func, req) { var m = { exports: {}, _tempexports: {} }; __MODS__[modId] = { status: 0, func: func, req: req, m: m }; };
var __REQUIRE__ = function(modId, source) { if(!__MODS__[modId]) return require(source); if(!__MODS__[modId].status) { var m = __MODS__[modId].m; m._exports = m._tempexports; var desp = Object.getOwnPropertyDescriptor(m, "exports"); if (desp && desp.configurable) Object.defineProperty(m, "exports", { set: function (val) { if(typeof val === "object" && val !== m._exports) { m._exports.__proto__ = val.__proto__; Object.keys(val).forEach(function (k) { m._exports[k] = val[k]; }); } m._tempexports = val }, get: function () { return m._tempexports; } }); __MODS__[modId].status = 1; __MODS__[modId].func(__MODS__[modId].req, m, m.exports); } return __MODS__[modId].m.exports; };
var __REQUIRE_WILDCARD__ = function(obj) { if(obj && obj.__esModule) { return obj; } else { var newObj = {}; if(obj != null) { for(var k in obj) { if (Object.prototype.hasOwnProperty.call(obj, k)) newObj[k] = obj[k]; } } newObj.default = obj; return newObj; } };
var __REQUIRE_DEFAULT__ = function(obj) { return obj && obj.__esModule ? obj.default : obj; };
__DEFINE__(1602998375458, function(require, module, exports) {

var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
var __generator = (this && this.__generator) || function (thisArg, body) {
    var _ = { label: 0, sent: function() { if (t[0] & 1) throw t[1]; return t[1]; }, trys: [], ops: [] }, f, y, t, g;
    return g = { next: verb(0), "throw": verb(1), "return": verb(2) }, typeof Symbol === "function" && (g[Symbol.iterator] = function() { return this; }), g;
    function verb(n) { return function (v) { return step([n, v]); }; }
    function step(op) {
        if (f) throw new TypeError("Generator is already executing.");
        while (_) try {
            if (f = 1, y && (t = op[0] & 2 ? y["return"] : op[0] ? y["throw"] || ((t = y["return"]) && t.call(y), 0) : y.next) && !(t = t.call(y, op[1])).done) return t;
            if (y = 0, t) op = [op[0] & 2, t.value];
            switch (op[0]) {
                case 0: case 1: t = op; break;
                case 4: _.label++; return { value: op[1], done: false };
                case 5: _.label++; y = op[1]; op = [0]; continue;
                case 7: op = _.ops.pop(); _.trys.pop(); continue;
                default:
                    if (!(t = _.trys, t = t.length > 0 && t[t.length - 1]) && (op[0] === 6 || op[0] === 2)) { _ = 0; continue; }
                    if (op[0] === 3 && (!t || (op[1] > t[0] && op[1] < t[3]))) { _.label = op[1]; break; }
                    if (op[0] === 6 && _.label < t[1]) { _.label = t[1]; t = op; break; }
                    if (t && _.label < t[2]) { _.label = t[2]; _.ops.push(op); break; }
                    if (t[2]) _.ops.pop();
                    _.trys.pop(); continue;
            }
            op = body.call(thisArg, _);
        } catch (e) { op = [6, e]; y = 0; } finally { f = t = 0; }
        if (op[0] & 5) throw op[1]; return { value: op[0] ? op[1] : void 0, done: true };
    }
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.upload = exports.request = void 0;
var adapter_utils_1 = require("@leancloud/adapter-utils");
var superagent = require("superagent");
function convertResponse(res) {
    return {
        ok: res.ok,
        status: res.status,
        headers: res.header,
        data: res.body,
    };
}
exports.request = function (url, options) {
    var _this = this;
    if (options === void 0) { options = {}; }
    var _a = options.method, method = _a === void 0 ? "GET" : _a, data = options.data, headers = options.headers, onprogress = options.onprogress, signal = options.signal;
    if (signal === null || signal === void 0 ? void 0 : signal.aborted) {
        return Promise.reject(new adapter_utils_1.AbortError("Request aborted"));
    }
    var req = superagent(method, url);
    if (headers) {
        req.set(headers);
    }
    if (onprogress) {
        req.on("progress", onprogress);
    }
    return new Promise(function (resolve, reject) { return __awaiter(_this, void 0, void 0, function () {
        var res, err_1, resErr;
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0:
                    if (signal) {
                        signal.addEventListener("abort", function () {
                            reject(new adapter_utils_1.AbortError("Request aborted"));
                            req.abort();
                        });
                    }
                    _a.label = 1;
                case 1:
                    _a.trys.push([1, 3, , 4]);
                    return [4 /*yield*/, req.send(data)];
                case 2:
                    res = _a.sent();
                    resolve(convertResponse(res));
                    return [3 /*break*/, 4];
                case 3:
                    err_1 = _a.sent();
                    resErr = err_1;
                    if (resErr.response) {
                        resolve(convertResponse(resErr.response));
                    }
                    else {
                        reject(err_1);
                    }
                    return [3 /*break*/, 4];
                case 4: return [2 /*return*/];
            }
        });
    }); });
};
exports.upload = function (url, file, options) {
    if (options === void 0) { options = {}; }
    var _a = options.method, method = _a === void 0 ? "POST" : _a, data = options.data, headers = options.headers, onprogress = options.onprogress, signal = options.signal;
    if (signal === null || signal === void 0 ? void 0 : signal.aborted) {
        return Promise.reject(new adapter_utils_1.AbortError("Request aborted"));
    }
    var req = superagent(method, url).attach(file.field, file.data, file.name);
    if (data) {
        req.field(data);
    }
    if (headers) {
        req.set(headers);
    }
    if (onprogress) {
        req.on("progress", onprogress);
    }
    return new Promise(function (resolve, reject) { return __awaiter(void 0, void 0, void 0, function () {
        var res, err_2, resErr;
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0:
                    if (signal) {
                        signal.addEventListener("abort", function () {
                            reject(new adapter_utils_1.AbortError("Request aborted"));
                            req.abort();
                        });
                    }
                    _a.label = 1;
                case 1:
                    _a.trys.push([1, 3, , 4]);
                    return [4 /*yield*/, req];
                case 2:
                    res = _a.sent();
                    resolve(convertResponse(res));
                    return [3 /*break*/, 4];
                case 3:
                    err_2 = _a.sent();
                    resErr = err_2;
                    if (resErr.response) {
                        resolve(convertResponse(resErr.response));
                    }
                    else {
                        reject(err_2);
                    }
                    return [3 /*break*/, 4];
                case 4: return [2 /*return*/];
            }
        });
    }); });
};
//# sourceMappingURL=index.js.map
}, function(modId) {var map = {}; return __REQUIRE__(map[modId], modId); })
return __REQUIRE__(1602998375458);
})()
//# sourceMappingURL=index.js.map
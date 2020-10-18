module.exports = (function() {
var __MODS__ = {};
var __DEFINE__ = function(modId, func, req) { var m = { exports: {}, _tempexports: {} }; __MODS__[modId] = { status: 0, func: func, req: req, m: m }; };
var __REQUIRE__ = function(modId, source) { if(!__MODS__[modId]) return require(source); if(!__MODS__[modId].status) { var m = __MODS__[modId].m; m._exports = m._tempexports; var desp = Object.getOwnPropertyDescriptor(m, "exports"); if (desp && desp.configurable) Object.defineProperty(m, "exports", { set: function (val) { if(typeof val === "object" && val !== m._exports) { m._exports.__proto__ = val.__proto__; Object.keys(val).forEach(function (k) { m._exports[k] = val[k]; }); } m._tempexports = val }, get: function () { return m._tempexports; } }); __MODS__[modId].status = 1; __MODS__[modId].func(__MODS__[modId].req, m, m.exports); } return __MODS__[modId].m.exports; };
var __REQUIRE_WILDCARD__ = function(obj) { if(obj && obj.__esModule) { return obj; } else { var newObj = {}; if(obj != null) { for(var k in obj) { if (Object.prototype.hasOwnProperty.call(obj, k)) newObj[k] = obj[k]; } } newObj.default = obj; return newObj; } };
var __REQUIRE_DEFAULT__ = function(obj) { return obj && obj.__esModule ? obj.default : obj; };
__DEFINE__(1603008214466, function(require, module, exports) {


function _typeof(obj) { "@babel/helpers - typeof"; if (typeof Symbol === "function" && typeof Symbol.iterator === "symbol") { _typeof = function _typeof(obj) { return typeof obj; }; } else { _typeof = function _typeof(obj) { return obj && typeof Symbol === "function" && obj.constructor === Symbol && obj !== Symbol.prototype ? "symbol" : typeof obj; }; } return _typeof(obj); }

/**
 * Module dependencies.
 */
// eslint-disable-next-line node/no-deprecated-api
var _require = require('url'),
    parse = _require.parse,
    format = _require.format,
    resolve = _require.resolve;

var Stream = require('stream');

var https = require('https');

var http = require('http');

var fs = require('fs');

var zlib = require('zlib');

var util = require('util');

var qs = require('qs');

var mime = require('mime');

var methods = require('methods');

var FormData = require('form-data');

var formidable = require('formidable');

var debug = require('debug')('superagent');

var CookieJar = require('cookiejar');

var semver = require('semver');

var safeStringify = require('fast-safe-stringify');

var utils = require('../utils');

var RequestBase = require('../request-base');

var _require2 = require('./unzip'),
    unzip = _require2.unzip;

var Response = require('./response');

var http2;
if (semver.gte(process.version, 'v10.10.0')) http2 = require('./http2wrapper');

function request(method, url) {
  // callback
  if (typeof url === 'function') {
    return new exports.Request('GET', method).end(url);
  } // url first


  if (arguments.length === 1) {
    return new exports.Request('GET', method);
  }

  return new exports.Request(method, url);
}

module.exports = request;
exports = module.exports;
/**
 * Expose `Request`.
 */

exports.Request = Request;
/**
 * Expose the agent function
 */

exports.agent = require('./agent');
/**
 * Noop.
 */

function noop() {}
/**
 * Expose `Response`.
 */


exports.Response = Response;
/**
 * Define "form" mime type.
 */

mime.define({
  'application/x-www-form-urlencoded': ['form', 'urlencoded', 'form-data']
}, true);
/**
 * Protocol map.
 */

exports.protocols = {
  'http:': http,
  'https:': https,
  'http2:': http2
};
/**
 * Default serialization map.
 *
 *     superagent.serialize['application/xml'] = function(obj){
 *       return 'generated xml here';
 *     };
 *
 */

exports.serialize = {
  'application/x-www-form-urlencoded': qs.stringify,
  'application/json': safeStringify
};
/**
 * Default parsers.
 *
 *     superagent.parse['application/xml'] = function(res, fn){
 *       fn(null, res);
 *     };
 *
 */

exports.parse = require('./parsers');
/**
 * Default buffering map. Can be used to set certain
 * response types to buffer/not buffer.
 *
 *     superagent.buffer['application/xml'] = true;
 */

exports.buffer = {};
/**
 * Initialize internal header tracking properties on a request instance.
 *
 * @param {Object} req the instance
 * @api private
 */

function _initHeaders(req) {
  req._header = {// coerces header names to lowercase
  };
  req.header = {// preserves header name case
  };
}
/**
 * Initialize a new `Request` with the given `method` and `url`.
 *
 * @param {String} method
 * @param {String|Object} url
 * @api public
 */


function Request(method, url) {
  Stream.call(this);
  if (typeof url !== 'string') url = format(url);
  this._enableHttp2 = Boolean(process.env.HTTP2_TEST); // internal only

  this._agent = false;
  this._formData = null;
  this.method = method;
  this.url = url;

  _initHeaders(this);

  this.writable = true;
  this._redirects = 0;
  this.redirects(method === 'HEAD' ? 0 : 5);
  this.cookies = '';
  this.qs = {};
  this._query = [];
  this.qsRaw = this._query; // Unused, for backwards compatibility only

  this._redirectList = [];
  this._streamRequest = false;
  this.once('end', this.clearTimeout.bind(this));
}
/**
 * Inherit from `Stream` (which inherits from `EventEmitter`).
 * Mixin `RequestBase`.
 */


util.inherits(Request, Stream); // eslint-disable-next-line new-cap

RequestBase(Request.prototype);
/**
 * Enable or Disable http2.
 *
 * Enable http2.
 *
 * ``` js
 * request.get('http://localhost/')
 *   .http2()
 *   .end(callback);
 *
 * request.get('http://localhost/')
 *   .http2(true)
 *   .end(callback);
 * ```
 *
 * Disable http2.
 *
 * ``` js
 * request = request.http2();
 * request.get('http://localhost/')
 *   .http2(false)
 *   .end(callback);
 * ```
 *
 * @param {Boolean} enable
 * @return {Request} for chaining
 * @api public
 */

Request.prototype.http2 = function (bool) {
  if (exports.protocols['http2:'] === undefined) {
    throw new Error('superagent: this version of Node.js does not support http2');
  }

  this._enableHttp2 = bool === undefined ? true : bool;
  return this;
};
/**
 * Queue the given `file` as an attachment to the specified `field`,
 * with optional `options` (or filename).
 *
 * ``` js
 * request.post('http://localhost/upload')
 *   .attach('field', Buffer.from('<b>Hello world</b>'), 'hello.html')
 *   .end(callback);
 * ```
 *
 * A filename may also be used:
 *
 * ``` js
 * request.post('http://localhost/upload')
 *   .attach('files', 'image.jpg')
 *   .end(callback);
 * ```
 *
 * @param {String} field
 * @param {String|fs.ReadStream|Buffer} file
 * @param {String|Object} options
 * @return {Request} for chaining
 * @api public
 */


Request.prototype.attach = function (field, file, options) {
  if (file) {
    if (this._data) {
      throw new Error("superagent can't mix .send() and .attach()");
    }

    var o = options || {};

    if (typeof options === 'string') {
      o = {
        filename: options
      };
    }

    if (typeof file === 'string') {
      if (!o.filename) o.filename = file;
      debug('creating `fs.ReadStream` instance for file: %s', file);
      file = fs.createReadStream(file);
    } else if (!o.filename && file.path) {
      o.filename = file.path;
    }

    this._getFormData().append(field, file, o);
  }

  return this;
};

Request.prototype._getFormData = function () {
  var _this = this;

  if (!this._formData) {
    this._formData = new FormData();

    this._formData.on('error', function (err) {
      debug('FormData error', err);

      if (_this.called) {
        // The request has already finished and the callback was called.
        // Silently ignore the error.
        return;
      }

      _this.callback(err);

      _this.abort();
    });
  }

  return this._formData;
};
/**
 * Gets/sets the `Agent` to use for this HTTP request. The default (if this
 * function is not called) is to opt out of connection pooling (`agent: false`).
 *
 * @param {http.Agent} agent
 * @return {http.Agent}
 * @api public
 */


Request.prototype.agent = function (agent) {
  if (arguments.length === 0) return this._agent;
  this._agent = agent;
  return this;
};
/**
 * Set _Content-Type_ response header passed through `mime.getType()`.
 *
 * Examples:
 *
 *      request.post('/')
 *        .type('xml')
 *        .send(xmlstring)
 *        .end(callback);
 *
 *      request.post('/')
 *        .type('json')
 *        .send(jsonstring)
 *        .end(callback);
 *
 *      request.post('/')
 *        .type('application/json')
 *        .send(jsonstring)
 *        .end(callback);
 *
 * @param {String} type
 * @return {Request} for chaining
 * @api public
 */


Request.prototype.type = function (type) {
  return this.set('Content-Type', type.includes('/') ? type : mime.getType(type));
};
/**
 * Set _Accept_ response header passed through `mime.getType()`.
 *
 * Examples:
 *
 *      superagent.types.json = 'application/json';
 *
 *      request.get('/agent')
 *        .accept('json')
 *        .end(callback);
 *
 *      request.get('/agent')
 *        .accept('application/json')
 *        .end(callback);
 *
 * @param {String} accept
 * @return {Request} for chaining
 * @api public
 */


Request.prototype.accept = function (type) {
  return this.set('Accept', type.includes('/') ? type : mime.getType(type));
};
/**
 * Add query-string `val`.
 *
 * Examples:
 *
 *   request.get('/shoes')
 *     .query('size=10')
 *     .query({ color: 'blue' })
 *
 * @param {Object|String} val
 * @return {Request} for chaining
 * @api public
 */


Request.prototype.query = function (val) {
  if (typeof val === 'string') {
    this._query.push(val);
  } else {
    Object.assign(this.qs, val);
  }

  return this;
};
/**
 * Write raw `data` / `encoding` to the socket.
 *
 * @param {Buffer|String} data
 * @param {String} encoding
 * @return {Boolean}
 * @api public
 */


Request.prototype.write = function (data, encoding) {
  var req = this.request();

  if (!this._streamRequest) {
    this._streamRequest = true;
  }

  return req.write(data, encoding);
};
/**
 * Pipe the request body to `stream`.
 *
 * @param {Stream} stream
 * @param {Object} options
 * @return {Stream}
 * @api public
 */


Request.prototype.pipe = function (stream, options) {
  this.piped = true; // HACK...

  this.buffer(false);
  this.end();
  return this._pipeContinue(stream, options);
};

Request.prototype._pipeContinue = function (stream, options) {
  var _this2 = this;

  this.req.once('response', function (res) {
    // redirect
    if (isRedirect(res.statusCode) && _this2._redirects++ !== _this2._maxRedirects) {
      return _this2._redirect(res) === _this2 ? _this2._pipeContinue(stream, options) : undefined;
    }

    _this2.res = res;

    _this2._emitResponse();

    if (_this2._aborted) return;

    if (_this2._shouldUnzip(res)) {
      var unzipObj = zlib.createUnzip();
      unzipObj.on('error', function (err) {
        if (err && err.code === 'Z_BUF_ERROR') {
          // unexpected end of file is ignored by browsers and curl
          stream.emit('end');
          return;
        }

        stream.emit('error', err);
      });
      res.pipe(unzipObj).pipe(stream, options);
    } else {
      res.pipe(stream, options);
    }

    res.once('end', function () {
      _this2.emit('end');
    });
  });
  return stream;
};
/**
 * Enable / disable buffering.
 *
 * @return {Boolean} [val]
 * @return {Request} for chaining
 * @api public
 */


Request.prototype.buffer = function (val) {
  this._buffer = val !== false;
  return this;
};
/**
 * Redirect to `url
 *
 * @param {IncomingMessage} res
 * @return {Request} for chaining
 * @api private
 */


Request.prototype._redirect = function (res) {
  var url = res.headers.location;

  if (!url) {
    return this.callback(new Error('No location header for redirect'), res);
  }

  debug('redirect %s -> %s', this.url, url); // location

  url = resolve(this.url, url); // ensure the response is being consumed
  // this is required for Node v0.10+

  res.resume();
  var headers = this.req.getHeaders ? this.req.getHeaders() : this.req._headers;
  var changesOrigin = parse(url).host !== parse(this.url).host; // implementation of 302 following defacto standard

  if (res.statusCode === 301 || res.statusCode === 302) {
    // strip Content-* related fields
    // in case of POST etc
    headers = utils.cleanHeader(headers, changesOrigin); // force GET

    this.method = this.method === 'HEAD' ? 'HEAD' : 'GET'; // clear data

    this._data = null;
  } // 303 is always GET


  if (res.statusCode === 303) {
    // strip Content-* related fields
    // in case of POST etc
    headers = utils.cleanHeader(headers, changesOrigin); // force method

    this.method = 'GET'; // clear data

    this._data = null;
  } // 307 preserves method
  // 308 preserves method


  delete headers.host;
  delete this.req;
  delete this._formData; // remove all add header except User-Agent

  _initHeaders(this); // redirect


  this._endCalled = false;
  this.url = url;
  this.qs = {};
  this._query.length = 0;
  this.set(headers);
  this.emit('redirect', res);

  this._redirectList.push(this.url);

  this.end(this._callback);
  return this;
};
/**
 * Set Authorization field value with `user` and `pass`.
 *
 * Examples:
 *
 *   .auth('tobi', 'learnboost')
 *   .auth('tobi:learnboost')
 *   .auth('tobi')
 *   .auth(accessToken, { type: 'bearer' })
 *
 * @param {String} user
 * @param {String} [pass]
 * @param {Object} [options] options with authorization type 'basic' or 'bearer' ('basic' is default)
 * @return {Request} for chaining
 * @api public
 */


Request.prototype.auth = function (user, pass, options) {
  if (arguments.length === 1) pass = '';

  if (_typeof(pass) === 'object' && pass !== null) {
    // pass is optional and can be replaced with options
    options = pass;
    pass = '';
  }

  if (!options) {
    options = {
      type: 'basic'
    };
  }

  var encoder = function encoder(string) {
    return Buffer.from(string).toString('base64');
  };

  return this._auth(user, pass, options, encoder);
};
/**
 * Set the certificate authority option for https request.
 *
 * @param {Buffer | Array} cert
 * @return {Request} for chaining
 * @api public
 */


Request.prototype.ca = function (cert) {
  this._ca = cert;
  return this;
};
/**
 * Set the client certificate key option for https request.
 *
 * @param {Buffer | String} cert
 * @return {Request} for chaining
 * @api public
 */


Request.prototype.key = function (cert) {
  this._key = cert;
  return this;
};
/**
 * Set the key, certificate, and CA certs of the client in PFX or PKCS12 format.
 *
 * @param {Buffer | String} cert
 * @return {Request} for chaining
 * @api public
 */


Request.prototype.pfx = function (cert) {
  if (_typeof(cert) === 'object' && !Buffer.isBuffer(cert)) {
    this._pfx = cert.pfx;
    this._passphrase = cert.passphrase;
  } else {
    this._pfx = cert;
  }

  return this;
};
/**
 * Set the client certificate option for https request.
 *
 * @param {Buffer | String} cert
 * @return {Request} for chaining
 * @api public
 */


Request.prototype.cert = function (cert) {
  this._cert = cert;
  return this;
};
/**
 * Do not reject expired or invalid TLS certs.
 * sets `rejectUnauthorized=true`. Be warned that this allows MITM attacks.
 *
 * @return {Request} for chaining
 * @api public
 */


Request.prototype.disableTLSCerts = function () {
  this._disableTLSCerts = true;
  return this;
};
/**
 * Return an http[s] request.
 *
 * @return {OutgoingMessage}
 * @api private
 */
// eslint-disable-next-line complexity


Request.prototype.request = function () {
  var _this3 = this;

  if (this.req) return this.req;
  var options = {};

  try {
    var query = qs.stringify(this.qs, {
      indices: false,
      strictNullHandling: true
    });

    if (query) {
      this.qs = {};

      this._query.push(query);
    }

    this._finalizeQueryString();
  } catch (err) {
    return this.emit('error', err);
  }

  var url = this.url;
  var retries = this._retries; // Capture backticks as-is from the final query string built above.
  // Note: this'll only find backticks entered in req.query(String)
  // calls, because qs.stringify unconditionally encodes backticks.

  var queryStringBackticks;

  if (url.includes('`')) {
    var queryStartIndex = url.indexOf('?');

    if (queryStartIndex !== -1) {
      var queryString = url.slice(queryStartIndex + 1);
      queryStringBackticks = queryString.match(/`|%60/g);
    }
  } // default to http://


  if (url.indexOf('http') !== 0) url = "http://".concat(url);
  url = parse(url); // See https://github.com/visionmedia/superagent/issues/1367

  if (queryStringBackticks) {
    var i = 0;
    url.query = url.query.replace(/%60/g, function () {
      return queryStringBackticks[i++];
    });
    url.search = "?".concat(url.query);
    url.path = url.pathname + url.search;
  } // support unix sockets


  if (/^https?\+unix:/.test(url.protocol) === true) {
    // get the protocol
    url.protocol = "".concat(url.protocol.split('+')[0], ":"); // get the socket, path

    var unixParts = url.path.match(/^([^/]+)(.+)$/);
    options.socketPath = unixParts[1].replace(/%2F/g, '/');
    url.path = unixParts[2];
  } // Override IP address of a hostname


  if (this._connectOverride) {
    var _url = url,
        hostname = _url.hostname;
    var match = hostname in this._connectOverride ? this._connectOverride[hostname] : this._connectOverride['*'];

    if (match) {
      // backup the real host
      if (!this._header.host) {
        this.set('host', url.host);
      }

      var newHost;
      var newPort;

      if (_typeof(match) === 'object') {
        newHost = match.host;
        newPort = match.port;
      } else {
        newHost = match;
        newPort = url.port;
      } // wrap [ipv6]


      url.host = /:/.test(newHost) ? "[".concat(newHost, "]") : newHost;

      if (newPort) {
        url.host += ":".concat(newPort);
        url.port = newPort;
      }

      url.hostname = newHost;
    }
  } // options


  options.method = this.method;
  options.port = url.port;
  options.path = url.path;
  options.host = url.hostname;
  options.ca = this._ca;
  options.key = this._key;
  options.pfx = this._pfx;
  options.cert = this._cert;
  options.passphrase = this._passphrase;
  options.agent = this._agent;
  options.rejectUnauthorized = typeof this._disableTLSCerts === 'boolean' ? !this._disableTLSCerts : process.env.NODE_TLS_REJECT_UNAUTHORIZED !== '0'; // Allows request.get('https://1.2.3.4/').set('Host', 'example.com')

  if (this._header.host) {
    options.servername = this._header.host.replace(/:\d+$/, '');
  }

  if (this._trustLocalhost && /^(?:localhost|127\.0\.0\.\d+|(0*:)+:0*1)$/.test(url.hostname)) {
    options.rejectUnauthorized = false;
  } // initiate request


  var mod = this._enableHttp2 ? exports.protocols['http2:'].setProtocol(url.protocol) : exports.protocols[url.protocol]; // request

  this.req = mod.request(options);
  var req = this.req; // set tcp no delay

  req.setNoDelay(true);

  if (options.method !== 'HEAD') {
    req.setHeader('Accept-Encoding', 'gzip, deflate');
  }

  this.protocol = url.protocol;
  this.host = url.host; // expose events

  req.once('drain', function () {
    _this3.emit('drain');
  });
  req.on('error', function (err) {
    // flag abortion here for out timeouts
    // because node will emit a faux-error "socket hang up"
    // when request is aborted before a connection is made
    if (_this3._aborted) return; // if not the same, we are in the **old** (cancelled) request,
    // so need to continue (same as for above)

    if (_this3._retries !== retries) return; // if we've received a response then we don't want to let
    // an error in the request blow up the response

    if (_this3.response) return;

    _this3.callback(err);
  }); // auth

  if (url.auth) {
    var auth = url.auth.split(':');
    this.auth(auth[0], auth[1]);
  }

  if (this.username && this.password) {
    this.auth(this.username, this.password);
  }

  for (var key in this.header) {
    if (Object.prototype.hasOwnProperty.call(this.header, key)) req.setHeader(key, this.header[key]);
  } // add cookies


  if (this.cookies) {
    if (Object.prototype.hasOwnProperty.call(this._header, 'cookie')) {
      // merge
      var tmpJar = new CookieJar.CookieJar();
      tmpJar.setCookies(this._header.cookie.split(';'));
      tmpJar.setCookies(this.cookies.split(';'));
      req.setHeader('Cookie', tmpJar.getCookies(CookieJar.CookieAccessInfo.All).toValueString());
    } else {
      req.setHeader('Cookie', this.cookies);
    }
  }

  return req;
};
/**
 * Invoke the callback with `err` and `res`
 * and handle arity check.
 *
 * @param {Error} err
 * @param {Response} res
 * @api private
 */


Request.prototype.callback = function (err, res) {
  if (this._shouldRetry(err, res)) {
    return this._retry();
  } // Avoid the error which is emitted from 'socket hang up' to cause the fn undefined error on JS runtime.


  var fn = this._callback || noop;
  this.clearTimeout();
  if (this.called) return console.warn('superagent: double callback bug');
  this.called = true;

  if (!err) {
    try {
      if (!this._isResponseOK(res)) {
        var msg = 'Unsuccessful HTTP response';

        if (res) {
          msg = http.STATUS_CODES[res.status] || msg;
        }

        err = new Error(msg);
        err.status = res ? res.status : undefined;
      }
    } catch (err_) {
      err = err_;
    }
  } // It's important that the callback is called outside try/catch
  // to avoid double callback


  if (!err) {
    return fn(null, res);
  }

  err.response = res;
  if (this._maxRetries) err.retries = this._retries - 1; // only emit error event if there is a listener
  // otherwise we assume the callback to `.end()` will get the error

  if (err && this.listeners('error').length > 0) {
    this.emit('error', err);
  }

  fn(err, res);
};
/**
 * Check if `obj` is a host object,
 *
 * @param {Object} obj host object
 * @return {Boolean} is a host object
 * @api private
 */


Request.prototype._isHost = function (obj) {
  return Buffer.isBuffer(obj) || obj instanceof Stream || obj instanceof FormData;
};
/**
 * Initiate request, invoking callback `fn(err, res)`
 * with an instanceof `Response`.
 *
 * @param {Function} fn
 * @return {Request} for chaining
 * @api public
 */


Request.prototype._emitResponse = function (body, files) {
  var response = new Response(this);
  this.response = response;
  response.redirects = this._redirectList;

  if (undefined !== body) {
    response.body = body;
  }

  response.files = files;

  if (this._endCalled) {
    response.pipe = function () {
      throw new Error("end() has already been called, so it's too late to start piping");
    };
  }

  this.emit('response', response);
  return response;
};

Request.prototype.end = function (fn) {
  this.request();
  debug('%s %s', this.method, this.url);

  if (this._endCalled) {
    throw new Error('.end() was called twice. This is not supported in superagent');
  }

  this._endCalled = true; // store callback

  this._callback = fn || noop;

  this._end();
};

Request.prototype._end = function () {
  var _this4 = this;

  if (this._aborted) return this.callback(new Error('The request has been aborted even before .end() was called'));
  var data = this._data;
  var req = this.req;
  var method = this.method;

  this._setTimeouts(); // body


  if (method !== 'HEAD' && !req._headerSent) {
    // serialize stuff
    if (typeof data !== 'string') {
      var contentType = req.getHeader('Content-Type'); // Parse out just the content type from the header (ignore the charset)

      if (contentType) contentType = contentType.split(';')[0];
      var serialize = this._serializer || exports.serialize[contentType];

      if (!serialize && isJSON(contentType)) {
        serialize = exports.serialize['application/json'];
      }

      if (serialize) data = serialize(data);
    } // content-length


    if (data && !req.getHeader('Content-Length')) {
      req.setHeader('Content-Length', Buffer.isBuffer(data) ? data.length : Buffer.byteLength(data));
    }
  } // response
  // eslint-disable-next-line complexity


  req.once('response', function (res) {
    debug('%s %s -> %s', _this4.method, _this4.url, res.statusCode);

    if (_this4._responseTimeoutTimer) {
      clearTimeout(_this4._responseTimeoutTimer);
    }

    if (_this4.piped) {
      return;
    }

    var max = _this4._maxRedirects;
    var mime = utils.type(res.headers['content-type'] || '') || 'text/plain';
    var type = mime.split('/')[0];
    var multipart = type === 'multipart';
    var redirect = isRedirect(res.statusCode);
    var responseType = _this4._responseType;
    _this4.res = res; // redirect

    if (redirect && _this4._redirects++ !== max) {
      return _this4._redirect(res);
    }

    if (_this4.method === 'HEAD') {
      _this4.emit('end');

      _this4.callback(null, _this4._emitResponse());

      return;
    } // zlib support


    if (_this4._shouldUnzip(res)) {
      unzip(req, res);
    }

    var buffer = _this4._buffer;

    if (buffer === undefined && mime in exports.buffer) {
      buffer = Boolean(exports.buffer[mime]);
    }

    var parser = _this4._parser;

    if (undefined === buffer) {
      if (parser) {
        console.warn("A custom superagent parser has been set, but buffering strategy for the parser hasn't been configured. Call `req.buffer(true or false)` or set `superagent.buffer[mime] = true or false`");
        buffer = true;
      }
    }

    if (!parser) {
      if (responseType) {
        parser = exports.parse.image; // It's actually a generic Buffer

        buffer = true;
      } else if (multipart) {
        var form = new formidable.IncomingForm();
        parser = form.parse.bind(form);
        buffer = true;
      } else if (isImageOrVideo(mime)) {
        parser = exports.parse.image;
        buffer = true; // For backwards-compatibility buffering default is ad-hoc MIME-dependent
      } else if (exports.parse[mime]) {
        parser = exports.parse[mime];
      } else if (type === 'text') {
        parser = exports.parse.text;
        buffer = buffer !== false; // everyone wants their own white-labeled json
      } else if (isJSON(mime)) {
        parser = exports.parse['application/json'];
        buffer = buffer !== false;
      } else if (buffer) {
        parser = exports.parse.text;
      } else if (undefined === buffer) {
        parser = exports.parse.image; // It's actually a generic Buffer

        buffer = true;
      }
    } // by default only buffer text/*, json and messed up thing from hell


    if (undefined === buffer && isText(mime) || isJSON(mime)) {
      buffer = true;
    }

    _this4._resBuffered = buffer;
    var parserHandlesEnd = false;

    if (buffer) {
      // Protectiona against zip bombs and other nuisance
      var responseBytesLeft = _this4._maxResponseSize || 200000000;
      res.on('data', function (buf) {
        responseBytesLeft -= buf.byteLength || buf.length;

        if (responseBytesLeft < 0) {
          // This will propagate through error event
          var err = new Error('Maximum response size reached');
          err.code = 'ETOOLARGE'; // Parsers aren't required to observe error event,
          // so would incorrectly report success

          parserHandlesEnd = false; // Will emit error event

          res.destroy(err);
        }
      });
    }

    if (parser) {
      try {
        // Unbuffered parsers are supposed to emit response early,
        // which is weird BTW, because response.body won't be there.
        parserHandlesEnd = buffer;
        parser(res, function (err, obj, files) {
          if (_this4.timedout) {
            // Timeout has already handled all callbacks
            return;
          } // Intentional (non-timeout) abort is supposed to preserve partial response,
          // even if it doesn't parse.


          if (err && !_this4._aborted) {
            return _this4.callback(err);
          }

          if (parserHandlesEnd) {
            _this4.emit('end');

            _this4.callback(null, _this4._emitResponse(obj, files));
          }
        });
      } catch (err) {
        _this4.callback(err);

        return;
      }
    }

    _this4.res = res; // unbuffered

    if (!buffer) {
      debug('unbuffered %s %s', _this4.method, _this4.url);

      _this4.callback(null, _this4._emitResponse());

      if (multipart) return; // allow multipart to handle end event

      res.once('end', function () {
        debug('end %s %s', _this4.method, _this4.url);

        _this4.emit('end');
      });
      return;
    } // terminating events


    res.once('error', function (err) {
      parserHandlesEnd = false;

      _this4.callback(err, null);
    });
    if (!parserHandlesEnd) res.once('end', function () {
      debug('end %s %s', _this4.method, _this4.url); // TODO: unless buffering emit earlier to stream

      _this4.emit('end');

      _this4.callback(null, _this4._emitResponse());
    });
  });
  this.emit('request', this);

  var getProgressMonitor = function getProgressMonitor() {
    var lengthComputable = true;
    var total = req.getHeader('Content-Length');
    var loaded = 0;
    var progress = new Stream.Transform();

    progress._transform = function (chunk, encoding, cb) {
      loaded += chunk.length;

      _this4.emit('progress', {
        direction: 'upload',
        lengthComputable: lengthComputable,
        loaded: loaded,
        total: total
      });

      cb(null, chunk);
    };

    return progress;
  };

  var bufferToChunks = function bufferToChunks(buffer) {
    var chunkSize = 16 * 1024; // default highWaterMark value

    var chunking = new Stream.Readable();
    var totalLength = buffer.length;
    var remainder = totalLength % chunkSize;
    var cutoff = totalLength - remainder;

    for (var i = 0; i < cutoff; i += chunkSize) {
      var chunk = buffer.slice(i, i + chunkSize);
      chunking.push(chunk);
    }

    if (remainder > 0) {
      var remainderBuffer = buffer.slice(-remainder);
      chunking.push(remainderBuffer);
    }

    chunking.push(null); // no more data

    return chunking;
  }; // if a FormData instance got created, then we send that as the request body


  var formData = this._formData;

  if (formData) {
    // set headers
    var headers = formData.getHeaders();

    for (var i in headers) {
      if (Object.prototype.hasOwnProperty.call(headers, i)) {
        debug('setting FormData header: "%s: %s"', i, headers[i]);
        req.setHeader(i, headers[i]);
      }
    } // attempt to get "Content-Length" header
    // eslint-disable-next-line handle-callback-err


    formData.getLength(function (err, length) {
      // TODO: Add chunked encoding when no length (if err)
      debug('got FormData Content-Length: %s', length);

      if (typeof length === 'number') {
        req.setHeader('Content-Length', length);
      }

      formData.pipe(getProgressMonitor()).pipe(req);
    });
  } else if (Buffer.isBuffer(data)) {
    bufferToChunks(data).pipe(getProgressMonitor()).pipe(req);
  } else {
    req.end(data);
  }
}; // Check whether response has a non-0-sized gzip-encoded body


Request.prototype._shouldUnzip = function (res) {
  if (res.statusCode === 204 || res.statusCode === 304) {
    // These aren't supposed to have any body
    return false;
  } // header content is a string, and distinction between 0 and no information is crucial


  if (res.headers['content-length'] === '0') {
    // We know that the body is empty (unfortunately, this check does not cover chunked encoding)
    return false;
  } // console.log(res);


  return /^\s*(?:deflate|gzip)\s*$/.test(res.headers['content-encoding']);
};
/**
 * Overrides DNS for selected hostnames. Takes object mapping hostnames to IP addresses.
 *
 * When making a request to a URL with a hostname exactly matching a key in the object,
 * use the given IP address to connect, instead of using DNS to resolve the hostname.
 *
 * A special host `*` matches every hostname (keep redirects in mind!)
 *
 *      request.connect({
 *        'test.example.com': '127.0.0.1',
 *        'ipv6.example.com': '::1',
 *      })
 */


Request.prototype.connect = function (connectOverride) {
  if (typeof connectOverride === 'string') {
    this._connectOverride = {
      '*': connectOverride
    };
  } else if (_typeof(connectOverride) === 'object') {
    this._connectOverride = connectOverride;
  } else {
    this._connectOverride = undefined;
  }

  return this;
};

Request.prototype.trustLocalhost = function (toggle) {
  this._trustLocalhost = toggle === undefined ? true : toggle;
  return this;
}; // generate HTTP verb methods


if (!methods.includes('del')) {
  // create a copy so we don't cause conflicts with
  // other packages using the methods package and
  // npm 3.x
  methods = methods.slice(0);
  methods.push('del');
}

methods.forEach(function (method) {
  var name = method;
  method = method === 'del' ? 'delete' : method;
  method = method.toUpperCase();

  request[name] = function (url, data, fn) {
    var req = request(method, url);

    if (typeof data === 'function') {
      fn = data;
      data = null;
    }

    if (data) {
      if (method === 'GET' || method === 'HEAD') {
        req.query(data);
      } else {
        req.send(data);
      }
    }

    if (fn) req.end(fn);
    return req;
  };
});
/**
 * Check if `mime` is text and should be buffered.
 *
 * @param {String} mime
 * @return {Boolean}
 * @api public
 */

function isText(mime) {
  var parts = mime.split('/');
  var type = parts[0];
  var subtype = parts[1];
  return type === 'text' || subtype === 'x-www-form-urlencoded';
}

function isImageOrVideo(mime) {
  var type = mime.split('/')[0];
  return type === 'image' || type === 'video';
}
/**
 * Check if `mime` is json or has +json structured syntax suffix.
 *
 * @param {String} mime
 * @return {Boolean}
 * @api private
 */


function isJSON(mime) {
  // should match /json or +json
  // but not /json-seq
  return /[/+]json($|[^-\w])/.test(mime);
}
/**
 * Check if we should follow the redirect `code`.
 *
 * @param {Number} code
 * @return {Boolean}
 * @api private
 */


function isRedirect(code) {
  return [301, 302, 303, 305, 307, 308].includes(code);
}
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbIi4uLy4uL3NyYy9ub2RlL2luZGV4LmpzIl0sIm5hbWVzIjpbInJlcXVpcmUiLCJwYXJzZSIsImZvcm1hdCIsInJlc29sdmUiLCJTdHJlYW0iLCJodHRwcyIsImh0dHAiLCJmcyIsInpsaWIiLCJ1dGlsIiwicXMiLCJtaW1lIiwibWV0aG9kcyIsIkZvcm1EYXRhIiwiZm9ybWlkYWJsZSIsImRlYnVnIiwiQ29va2llSmFyIiwic2VtdmVyIiwic2FmZVN0cmluZ2lmeSIsInV0aWxzIiwiUmVxdWVzdEJhc2UiLCJ1bnppcCIsIlJlc3BvbnNlIiwiaHR0cDIiLCJndGUiLCJwcm9jZXNzIiwidmVyc2lvbiIsInJlcXVlc3QiLCJtZXRob2QiLCJ1cmwiLCJleHBvcnRzIiwiUmVxdWVzdCIsImVuZCIsImFyZ3VtZW50cyIsImxlbmd0aCIsIm1vZHVsZSIsImFnZW50Iiwibm9vcCIsImRlZmluZSIsInByb3RvY29scyIsInNlcmlhbGl6ZSIsInN0cmluZ2lmeSIsImJ1ZmZlciIsIl9pbml0SGVhZGVycyIsInJlcSIsIl9oZWFkZXIiLCJoZWFkZXIiLCJjYWxsIiwiX2VuYWJsZUh0dHAyIiwiQm9vbGVhbiIsImVudiIsIkhUVFAyX1RFU1QiLCJfYWdlbnQiLCJfZm9ybURhdGEiLCJ3cml0YWJsZSIsIl9yZWRpcmVjdHMiLCJyZWRpcmVjdHMiLCJjb29raWVzIiwiX3F1ZXJ5IiwicXNSYXciLCJfcmVkaXJlY3RMaXN0IiwiX3N0cmVhbVJlcXVlc3QiLCJvbmNlIiwiY2xlYXJUaW1lb3V0IiwiYmluZCIsImluaGVyaXRzIiwicHJvdG90eXBlIiwiYm9vbCIsInVuZGVmaW5lZCIsIkVycm9yIiwiYXR0YWNoIiwiZmllbGQiLCJmaWxlIiwib3B0aW9ucyIsIl9kYXRhIiwibyIsImZpbGVuYW1lIiwiY3JlYXRlUmVhZFN0cmVhbSIsInBhdGgiLCJfZ2V0Rm9ybURhdGEiLCJhcHBlbmQiLCJvbiIsImVyciIsImNhbGxlZCIsImNhbGxiYWNrIiwiYWJvcnQiLCJ0eXBlIiwic2V0IiwiaW5jbHVkZXMiLCJnZXRUeXBlIiwiYWNjZXB0IiwicXVlcnkiLCJ2YWwiLCJwdXNoIiwiT2JqZWN0IiwiYXNzaWduIiwid3JpdGUiLCJkYXRhIiwiZW5jb2RpbmciLCJwaXBlIiwic3RyZWFtIiwicGlwZWQiLCJfcGlwZUNvbnRpbnVlIiwicmVzIiwiaXNSZWRpcmVjdCIsInN0YXR1c0NvZGUiLCJfbWF4UmVkaXJlY3RzIiwiX3JlZGlyZWN0IiwiX2VtaXRSZXNwb25zZSIsIl9hYm9ydGVkIiwiX3Nob3VsZFVuemlwIiwidW56aXBPYmoiLCJjcmVhdGVVbnppcCIsImNvZGUiLCJlbWl0IiwiX2J1ZmZlciIsImhlYWRlcnMiLCJsb2NhdGlvbiIsInJlc3VtZSIsImdldEhlYWRlcnMiLCJfaGVhZGVycyIsImNoYW5nZXNPcmlnaW4iLCJob3N0IiwiY2xlYW5IZWFkZXIiLCJfZW5kQ2FsbGVkIiwiX2NhbGxiYWNrIiwiYXV0aCIsInVzZXIiLCJwYXNzIiwiZW5jb2RlciIsInN0cmluZyIsIkJ1ZmZlciIsImZyb20iLCJ0b1N0cmluZyIsIl9hdXRoIiwiY2EiLCJjZXJ0IiwiX2NhIiwia2V5IiwiX2tleSIsInBmeCIsImlzQnVmZmVyIiwiX3BmeCIsIl9wYXNzcGhyYXNlIiwicGFzc3BocmFzZSIsIl9jZXJ0IiwiZGlzYWJsZVRMU0NlcnRzIiwiX2Rpc2FibGVUTFNDZXJ0cyIsImluZGljZXMiLCJzdHJpY3ROdWxsSGFuZGxpbmciLCJfZmluYWxpemVRdWVyeVN0cmluZyIsInJldHJpZXMiLCJfcmV0cmllcyIsInF1ZXJ5U3RyaW5nQmFja3RpY2tzIiwicXVlcnlTdGFydEluZGV4IiwiaW5kZXhPZiIsInF1ZXJ5U3RyaW5nIiwic2xpY2UiLCJtYXRjaCIsImkiLCJyZXBsYWNlIiwic2VhcmNoIiwicGF0aG5hbWUiLCJ0ZXN0IiwicHJvdG9jb2wiLCJzcGxpdCIsInVuaXhQYXJ0cyIsInNvY2tldFBhdGgiLCJfY29ubmVjdE92ZXJyaWRlIiwiaG9zdG5hbWUiLCJuZXdIb3N0IiwibmV3UG9ydCIsInBvcnQiLCJyZWplY3RVbmF1dGhvcml6ZWQiLCJOT0RFX1RMU19SRUpFQ1RfVU5BVVRIT1JJWkVEIiwic2VydmVybmFtZSIsIl90cnVzdExvY2FsaG9zdCIsIm1vZCIsInNldFByb3RvY29sIiwic2V0Tm9EZWxheSIsInNldEhlYWRlciIsInJlc3BvbnNlIiwidXNlcm5hbWUiLCJwYXNzd29yZCIsImhhc093blByb3BlcnR5IiwidG1wSmFyIiwic2V0Q29va2llcyIsImNvb2tpZSIsImdldENvb2tpZXMiLCJDb29raWVBY2Nlc3NJbmZvIiwiQWxsIiwidG9WYWx1ZVN0cmluZyIsIl9zaG91bGRSZXRyeSIsIl9yZXRyeSIsImZuIiwiY29uc29sZSIsIndhcm4iLCJfaXNSZXNwb25zZU9LIiwibXNnIiwiU1RBVFVTX0NPREVTIiwic3RhdHVzIiwiZXJyXyIsIl9tYXhSZXRyaWVzIiwibGlzdGVuZXJzIiwiX2lzSG9zdCIsIm9iaiIsImJvZHkiLCJmaWxlcyIsIl9lbmQiLCJfc2V0VGltZW91dHMiLCJfaGVhZGVyU2VudCIsImNvbnRlbnRUeXBlIiwiZ2V0SGVhZGVyIiwiX3NlcmlhbGl6ZXIiLCJpc0pTT04iLCJieXRlTGVuZ3RoIiwiX3Jlc3BvbnNlVGltZW91dFRpbWVyIiwibWF4IiwibXVsdGlwYXJ0IiwicmVkaXJlY3QiLCJyZXNwb25zZVR5cGUiLCJfcmVzcG9uc2VUeXBlIiwicGFyc2VyIiwiX3BhcnNlciIsImltYWdlIiwiZm9ybSIsIkluY29taW5nRm9ybSIsImlzSW1hZ2VPclZpZGVvIiwidGV4dCIsImlzVGV4dCIsIl9yZXNCdWZmZXJlZCIsInBhcnNlckhhbmRsZXNFbmQiLCJyZXNwb25zZUJ5dGVzTGVmdCIsIl9tYXhSZXNwb25zZVNpemUiLCJidWYiLCJkZXN0cm95IiwidGltZWRvdXQiLCJnZXRQcm9ncmVzc01vbml0b3IiLCJsZW5ndGhDb21wdXRhYmxlIiwidG90YWwiLCJsb2FkZWQiLCJwcm9ncmVzcyIsIlRyYW5zZm9ybSIsIl90cmFuc2Zvcm0iLCJjaHVuayIsImNiIiwiZGlyZWN0aW9uIiwiYnVmZmVyVG9DaHVua3MiLCJjaHVua1NpemUiLCJjaHVua2luZyIsIlJlYWRhYmxlIiwidG90YWxMZW5ndGgiLCJyZW1haW5kZXIiLCJjdXRvZmYiLCJyZW1haW5kZXJCdWZmZXIiLCJmb3JtRGF0YSIsImdldExlbmd0aCIsImNvbm5lY3QiLCJjb25uZWN0T3ZlcnJpZGUiLCJ0cnVzdExvY2FsaG9zdCIsInRvZ2dsZSIsImZvckVhY2giLCJuYW1lIiwidG9VcHBlckNhc2UiLCJzZW5kIiwicGFydHMiLCJzdWJ0eXBlIl0sIm1hcHBpbmdzIjoiOzs7O0FBQUE7OztBQUlBO2VBQ21DQSxPQUFPLENBQUMsS0FBRCxDO0lBQWxDQyxLLFlBQUFBLEs7SUFBT0MsTSxZQUFBQSxNO0lBQVFDLE8sWUFBQUEsTzs7QUFDdkIsSUFBTUMsTUFBTSxHQUFHSixPQUFPLENBQUMsUUFBRCxDQUF0Qjs7QUFDQSxJQUFNSyxLQUFLLEdBQUdMLE9BQU8sQ0FBQyxPQUFELENBQXJCOztBQUNBLElBQU1NLElBQUksR0FBR04sT0FBTyxDQUFDLE1BQUQsQ0FBcEI7O0FBQ0EsSUFBTU8sRUFBRSxHQUFHUCxPQUFPLENBQUMsSUFBRCxDQUFsQjs7QUFDQSxJQUFNUSxJQUFJLEdBQUdSLE9BQU8sQ0FBQyxNQUFELENBQXBCOztBQUNBLElBQU1TLElBQUksR0FBR1QsT0FBTyxDQUFDLE1BQUQsQ0FBcEI7O0FBQ0EsSUFBTVUsRUFBRSxHQUFHVixPQUFPLENBQUMsSUFBRCxDQUFsQjs7QUFDQSxJQUFNVyxJQUFJLEdBQUdYLE9BQU8sQ0FBQyxNQUFELENBQXBCOztBQUNBLElBQUlZLE9BQU8sR0FBR1osT0FBTyxDQUFDLFNBQUQsQ0FBckI7O0FBQ0EsSUFBTWEsUUFBUSxHQUFHYixPQUFPLENBQUMsV0FBRCxDQUF4Qjs7QUFDQSxJQUFNYyxVQUFVLEdBQUdkLE9BQU8sQ0FBQyxZQUFELENBQTFCOztBQUNBLElBQU1lLEtBQUssR0FBR2YsT0FBTyxDQUFDLE9BQUQsQ0FBUCxDQUFpQixZQUFqQixDQUFkOztBQUNBLElBQU1n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QUFFQSxTQUFPL0UsSUFBSSxLQUFLLE9BQVQsSUFBb0JBLElBQUksS0FBSyxPQUFwQztBQUNEO0FBRUQ7Ozs7Ozs7OztBQVFBLFNBQVNnSSxNQUFULENBQWdCM00sSUFBaEIsRUFBc0I7QUFDcEI7QUFDQTtBQUNBLFNBQU8scUJBQXFCd0osSUFBckIsQ0FBMEJ4SixJQUExQixDQUFQO0FBQ0Q7QUFFRDs7Ozs7Ozs7O0FBUUEsU0FBUzZGLFVBQVQsQ0FBb0JTLElBQXBCLEVBQTBCO0FBQ3hCLFNBQU8sQ0FBQyxHQUFELEVBQU0sR0FBTixFQUFXLEdBQVgsRUFBZ0IsR0FBaEIsRUFBcUIsR0FBckIsRUFBMEIsR0FBMUIsRUFBK0J6QixRQUEvQixDQUF3Q3lCLElBQXhDLENBQVA7QUFDRCIsInNvdXJjZXNDb250ZW50IjpbIi8qKlxuICogTW9kdWxlIGRlcGVuZGVuY2llcy5cbiAqL1xuXG4vLyBlc2xpbnQtZGlzYWJsZS1uZXh0LWxpbmUgbm9kZS9uby1kZXByZWNhdGVkLWFwaVxuY29uc3QgeyBwYXJzZSwgZm9ybWF0LCByZXNvbHZlIH0gPSByZXF1aXJlKCd1cmwnKTtcbmNvbnN0IFN0cmVhbSA9IHJlcXVpcmUoJ3N0cmVhbScpO1xuY29uc3QgaHR0cHMgPSByZXF1aXJlKCdodHRwcycpO1xuY29uc3QgaHR0cCA9IHJlcXVpcmUoJ2h0dHAnKTtcbmNvbnN0IGZzID0gcmVxdWlyZSgnZnMnKTtcbmNvbnN0IHpsaWIgPSByZXF1aXJlKCd6bGliJyk7XG5jb25zdCB1dGlsID0gcmVxdWlyZSgndXRpbCcpO1xuY29uc3QgcXMgPSByZXF1aXJlKCdxcycpO1xuY29uc3QgbWltZSA9IHJlcXVpcmUoJ21pbWUnKTtcbmxldCBtZXRob2RzID0gcmVxdWlyZSgnbWV0aG9kcycpO1xuY29uc3QgRm9ybURhdGEgPSByZXF1aXJlKCdmb3JtLWRhdGEnKTtcbmNvbnN0IGZvcm1pZGFibGUgPSByZXF1aXJlKCdmb3JtaWRhYmxlJyk7XG5jb25zdCBkZWJ1ZyA9IHJlcXVpcmUoJ2RlYnVnJykoJ3N1cGVyYWdlbnQnKTtcbmNvbnN0IENvb2tpZUphciA9IHJlcXVpcmUoJ2Nvb2tpZWphcicpO1xuY29uc3Qgc2VtdmVyID0gcmVxdWlyZSgnc2VtdmVyJyk7XG5jb25zdCBzYWZlU3RyaW5naWZ5ID0gcmVxdWlyZSgnZmFzdC1zYWZlLXN0cmluZ2lmeScpO1xuXG5jb25zdCB1dGlscyA9IHJlcXVpcmUoJy4uL3V0aWxzJyk7XG5jb25zdCBSZXF1ZXN0QmFzZSA9IHJlcXVpcmUoJy4uL3JlcXVlc3QtYmFzZScpO1xuY29uc3QgeyB1bnppcCB9ID0gcmVxdWlyZSgnLi91bnppcCcpO1xuY29uc3QgUmVzcG9uc2UgPSByZXF1aXJlKCcuL3Jlc3BvbnNlJyk7XG5cbmxldCBodHRwMjtcblxuaWYgKHNlbXZlci5ndGUocHJvY2Vzcy52ZXJzaW9uLCAndjEwLjEwLjAnKSkgaHR0cDIgPSByZXF1aXJlKCcuL2h0dHAyd3JhcHBlcicpO1xuXG5mdW5jdGlvbiByZXF1ZXN0KG1ldGhvZCwgdXJsKSB7XG4gIC8vIGNhbGxiYWNrXG4gIGlmICh0eXBlb2YgdXJsID09PSAnZnVuY3Rpb24nKSB7XG4gICAgcmV0dXJuIG5ldyBleHBvcnRzLlJlcXVlc3QoJ0dFVCcsIG1ldGhvZCkuZW5kKHVybCk7XG4gIH1cblxuICAvLyB1cmwgZmlyc3RcbiAgaWYgKGFyZ3VtZW50cy5sZW5ndGggPT09IDEpIHtcbiAgICByZXR1cm4gbmV3IGV4cG9ydHMuUmVxdWVzdCgnR0VUJywgbWV0aG9kKTtcbiAgfVxuXG4gIHJldHVybiBuZXcgZXhwb3J0cy5SZXF1ZXN0KG1ldGhvZCwgdXJsKTtcbn1cblxubW9kdWxlLmV4cG9ydHMgPSByZXF1ZXN0O1xuZXhwb3J0cyA9IG1vZHVsZS5leHBvcnRzO1xuXG4vKipcbiAqIEV4cG9zZSBgUmVxdWVzdGAuXG4gKi9cblxuZXhwb3J0cy5SZXF1ZXN0ID0gUmVxdWVzdDtcblxuLyoqXG4gKiBFeHBvc2UgdGhlIGFnZW50IGZ1bmN0aW9uXG4gKi9cblxuZXhwb3J0cy5hZ2VudCA9IHJlcXVpcmUoJy4vYWdlbnQnKTtcblxuLyoqXG4gKiBOb29wLlxuICovXG5cbmZ1bmN0aW9uIG5vb3AoKSB7fVxuXG4vKipcbiAqIEV4cG9zZSBgUmVzcG9uc2VgLlxuICovXG5cbmV4cG9ydHMuUmVzcG9uc2UgPSBSZXNwb25zZTtcblxuLyoqXG4gKiBEZWZpbmUgXCJmb3JtXCIgbWltZSB0eXBlLlxuICovXG5cbm1pbWUuZGVmaW5lKFxuICB7XG4gICAgJ2FwcGxpY2F0aW9uL3gtd3d3LWZvcm0tdXJsZW5jb2RlZCc6IFsnZm9ybScsICd1cmxlbmNvZGVkJywgJ2Zvcm0tZGF0YSddXG4gIH0sXG4gIHRydWVcbik7XG5cbi8qKlxuICogUHJvdG9jb2wgbWFwLlxuICovXG5cbmV4cG9ydHMucHJvdG9jb2xzID0ge1xuICAnaHR0cDonOiBodHRwLFxuICAnaHR0cHM6JzogaHR0cHMsXG4gICdodHRwMjonOiBodHRwMlxufTtcblxuLyoqXG4gKiBEZWZhdWx0IHNlcmlhbGl6YXRpb24gbWFwLlxuICpcbiAqICAgICBzdXBlcmFnZW50LnNlcmlhbGl6ZVsnYXBwbGljYXRpb24veG1sJ10gPSBmdW5jdGlvbihvYmope1xuICogICAgICAgcmV0dXJuICdnZW5lcmF0ZWQgeG1sIGhlcmUnO1xuICogICAgIH07XG4gKlxuICovXG5cbmV4cG9ydHMuc2VyaWFsaXplID0ge1xuICAnYXBwbGljYXRpb24veC13d3ctZm9ybS11cmxlbmNvZGVkJzogcXMuc3RyaW5naWZ5LFxuICAnYXBwbGljYXRpb24vanNvbic6IHNhZmVTdHJpbmdpZnlcbn07XG5cbi8qKlxuICogRGVmYXVsdCBwYXJzZXJzLlxuICpcbiAqICAgICBzdXBlcmFnZW50LnBhcnNlWydhcHBsaWNhdGlvbi94bWwnXSA9IGZ1bmN0aW9uKHJlcywgZm4pe1xuICogICAgICAgZm4obnVsbCwgcmVzKTtcbiAqICAgICB9O1xuICpcbiAqL1xuXG5leHBvcnRzLnBhcnNlID0gcmVxdWlyZSgnLi9wYXJzZXJzJyk7XG5cbi8qKlxuICogRGVmYXVsdCBidWZmZXJpbmcgbWFwLiBDYW4gYmUgdXNlZCB0byBzZXQgY2VydGFpblxuICogcmVzcG9uc2UgdHlwZXMgdG8gYnVmZmVyL25vdCBidWZmZXIuXG4gKlxuICogICAgIHN1cGVyYWdlbnQuYnVmZmVyWydhcHBsaWNhdGlvbi94bWwnXSA9IHRydWU7XG4gKi9cbmV4cG9ydHMuYnVmZmVyID0ge307XG5cbi8qKlxuICogSW5pdGlhbGl6ZSBpbnRlcm5hbCBoZWFkZXIgdHJhY2tpbmcgcHJvcGVydGllcyBvbiBhIHJlcXVlc3QgaW5zdGFuY2UuXG4gKlxuICogQHBhcmFtIHtPYmplY3R9IHJlcSB0aGUgaW5zdGFuY2VcbiAqIEBhcGkgcHJpdmF0ZVxuICovXG5mdW5jdGlvbiBfaW5pdEhlYWRlcnMocmVxKSB7XG4gIHJlcS5faGVhZGVyID0ge1xuICAgIC8vIGNvZXJjZXMgaGVhZGVyIG5hbWVzIHRvIGxvd2VyY2FzZVxuICB9O1xuICByZXEuaGVhZGVyID0ge1xuICAgIC8vIHByZXNlcnZlcyBoZWFkZXIgbmFtZSBjYXNlXG4gIH07XG59XG5cbi8qKlxuICogSW5pdGlhbGl6ZSBhIG5ldyBgUmVxdWVzdGAgd2l0aCB0aGUgZ2l2ZW4gYG1ldGhvZGAgYW5kIGB1cmxgLlxuICpcbiAqIEBwYXJhbSB7U3RyaW5nfSBtZXRob2RcbiAqIEBwYXJhbSB7U3RyaW5nfE9iamVjdH0gdXJsXG4gKiBAYXBpIHB1YmxpY1xuICovXG5cbmZ1bmN0aW9uIFJlcXVlc3QobWV0aG9kLCB1cmwpIHtcbiAgU3RyZWFtLmNhbGwodGhpcyk7XG4gIGlmICh0eXBlb2YgdXJsICE9PSAnc3RyaW5nJykgdXJsID0gZm9ybWF0KHVybCk7XG4gIHRoaXMuX2VuYWJsZUh0dHAyID0gQm9vbGVhbihwcm9jZXNzLmVudi5IVFRQMl9URVNUKTsgLy8gaW50ZXJuYWwgb25seVxuICB0aGlzLl9hZ2VudCA9IGZhbHNlO1xuICB0aGlzLl9mb3JtRGF0YSA9IG51bGw7XG4gIHRoaXMubWV0aG9kID0gbWV0aG9kO1xuICB0aGlzLnVybCA9IHVybDtcbiAgX2luaXRIZWFkZXJzKHRoaXMpO1xuICB0aGlzLndyaXRhYmxlID0gdHJ1ZTtcbiAgdGhpcy5fcmVkaXJlY3RzID0gMDtcbiAgdGhpcy5yZWRpcmVjdHMobWV0aG9kID09PSAnSEVBRCcgPyAwIDogNSk7XG4gIHRoaXMuY29va2llcyA9ICcnO1xuICB0aGlzLnFzID0ge307XG4gIHRoaXMuX3F1ZXJ5ID0gW107XG4gIHRoaXMucXNSYXcgPSB0aGlzLl9xdWVyeTsgLy8gVW51c2VkLCBmb3IgYmFja3dhcmRzIGNvbXBhdGliaWxpdHkgb25seVxuICB0aGlzLl9yZWRpcmVjdExpc3QgPSBbXTtcbiAgdGhpcy5fc3RyZWFtUmVxdWVzdCA9IGZhbHNlO1xuICB0aGlzLm9uY2UoJ2VuZCcsIHRoaXMuY2xlYXJUaW1lb3V0LmJpbmQodGhpcykpO1xufVxuXG4vKipcbiAqIEluaGVyaXQgZnJvbSBgU3RyZWFtYCAod2hpY2ggaW5oZXJpdHMgZnJvbSBgRXZlbnRFbWl0dGVyYCkuXG4gKiBNaXhpbiBgUmVxdWVzdEJhc2VgLlxuICovXG51dGlsLmluaGVyaXRzKFJlcXVlc3QsIFN0cmVhbSk7XG4vLyBlc2xpbnQtZGlzYWJsZS1uZXh0LWxpbmUgbmV3LWNhcFxuUmVxdWVzdEJhc2UoUmVxdWVzdC5wcm90b3R5cGUpO1xuXG4vKipcbiAqIEVuYWJsZSBvciBEaXNhYmxlIGh0dHAyLlxuICpcbiAqIEVuYWJsZSBodHRwMi5cbiAqXG4gKiBgYGAganNcbiAqIHJlcXVlc3QuZ2V0KCdodHRwOi8vbG9jYWxob3N0LycpXG4gKiAgIC5odHRwMigpXG4gKiAgIC5lbmQoY2FsbGJhY2spO1xuICpcbiAqIHJlcXVlc3QuZ2V0KCdodHRwOi8vbG9jYWxob3N0LycpXG4gKiAgIC5odHRwMih0cnVlKVxuICogICAuZW5kKGNhbGxiYWNrKTtcbiAqIGBgYFxuICpcbiAqIERpc2FibGUgaHR0cDIuXG4gKlxuICogYGBgIGpzXG4gKiByZXF1ZXN0ID0gcmVxdWVzdC5odHRwMigpO1xuICogcmVxdWVzdC5nZXQoJ2h0dHA6Ly9sb2NhbGhvc3QvJylcbiAqICAgLmh0dHAyKGZhbHNlKVxuICogICAuZW5kKGNhbGxiYWNrKTtcbiAqIGBgYFxuICpcbiAqIEBwYXJhbSB7Qm9vbGVhbn0gZW5hYmxlXG4gKiBAcmV0dXJuIHtSZXF1ZXN0fSBmb3IgY2hhaW5pbmdcbiAqIEBhcGkgcHVibGljXG4gKi9cblxuUmVxdWVzdC5wcm90b3R5cGUuaHR0cDIgPSBmdW5jdGlvbihib29sKSB7XG4gIGlmIChleHBvcnRzLnByb3RvY29sc1snaHR0cDI6J10gPT09IHVuZGVmaW5lZCkge1xuICAgIHRocm93IG5ldyBFcnJvcihcbiAgICAgICdzdXBlcmFnZW50OiB0aGlzIHZlcnNpb24gb2YgTm9kZS5qcyBkb2VzIG5vdCBzdXBwb3J0IGh0dHAyJ1xuICAgICk7XG4gIH1cblxuICB0aGlzLl9lbmFibGVIdHRwMiA9IGJvb2wgPT09IHVuZGVmaW5lZCA/IHRydWUgOiBib29sO1xuICByZXR1cm4gdGhpcztcbn07XG5cbi8qKlxuICogUXVldWUgdGhlIGdpdmVuIGBmaWxlYCBhcyBhbiBhdHRhY2htZW50IHRvIHRoZSBzcGVjaWZpZWQgYGZpZWxkYCxcbiAqIHdpdGggb3B0aW9uYWwgYG9wdGlvbnNgIChvciBmaWxlbmFtZSkuXG4gKlxuICogYGBgIGpzXG4gKiByZXF1ZXN0LnBvc3QoJ2h0dHA6Ly9sb2NhbGhvc3QvdXBsb2FkJylcbiAqICAgLmF0dGFjaCgnZmllbGQnLCBCdWZmZXIuZnJvbSgnPGI+SGVsbG8gd29ybGQ8L2I+JyksICdoZWxsby5odG1sJylcbiAqICAgLmVuZChjYWxsYmFjayk7XG4gKiBgYGBcbiAqXG4gKiBBIGZpbGVuYW1lIG1heSBhbHNvIGJlIHVzZWQ6XG4gKlxuICogYGBgIGpzXG4gKiByZXF1ZXN0LnBvc3QoJ2h0dHA6Ly9sb2NhbGhvc3QvdXBsb2FkJylcbiAqICAgLmF0dGFjaCgnZmlsZXMnLCAnaW1hZ2UuanBnJylcbiAqICAgLmVuZChjYWxsYmFjayk7XG4gKiBgYGBcbiAqXG4gKiBAcGFyYW0ge1N0cmluZ30gZmllbGRcbiAqIEBwYXJhbSB7U3RyaW5nfGZzLlJlYWRTdHJlYW18QnVmZmVyfSBmaWxlXG4gKiBAcGFyYW0ge1N0cmluZ3xPYmplY3R9IG9wdGlvbnNcbiAqIEByZXR1cm4ge1JlcXVlc3R9IGZvciBjaGFpbmluZ1xuICogQGFwaSBwdWJsaWNcbiAqL1xuXG5SZXF1ZXN0LnByb3RvdHlwZS5hdHRhY2ggPSBmdW5jdGlvbihmaWVsZCwgZmlsZSwgb3B0aW9ucykge1xuICBpZiAoZmlsZSkge1xuICAgIGlmICh0aGlzLl9kYXRhKSB7XG4gICAgICB0aHJvdyBuZXcgRXJyb3IoXCJzdXBlcmFnZW50IGNhbid0IG1peCAuc2VuZCgpIGFuZCAuYXR0YWNoKClcIik7XG4gICAgfVxuXG4gICAgbGV0IG8gPSBvcHRpb25zIHx8IHt9O1xuICAgIGlmICh0eXBlb2Ygb3B0aW9ucyA9PT0gJ3N0cmluZycpIHtcbiAgICAgIG8gPSB7IGZpbGVuYW1lOiBvcHRpb25zIH07XG4gICAgfVxuXG4gICAgaWYgKHR5cGVvZiBmaWxlID09PSAnc3RyaW5nJykge1xuICAgICAgaWYgKCFvLmZpbGVuYW1lKSBvLmZpbGVuYW1lID0gZmlsZTtcbiAgICAgIGRlYnVnKCdjcmVhdGluZyBgZnMuUmVhZFN0cmVhbWAgaW5zdGFuY2UgZm9yIGZpbGU6ICVzJywgZmlsZSk7XG4gICAgICBmaWxlID0gZnMuY3JlYXRlUmVhZFN0cmVhbShmaWxlKTtcbiAgICB9IGVsc2UgaWYgKCFvLmZpbGVuYW1lICYmIGZpbGUucGF0aCkge1xuICAgICAgby5maWxlbmFtZSA9IGZpbGUucGF0aDtcbiAgICB9XG5cbiAgICB0aGlzLl9nZXRGb3JtRGF0YSgpLmFwcGVuZChmaWVsZCwgZmlsZSwgbyk7XG4gIH1cblxuICByZXR1cm4gdGhpcztcbn07XG5cblJlcXVlc3QucHJvdG90eXBlLl9nZXRGb3JtRGF0YSA9IGZ1bmN0aW9uKCkge1xuICBpZiAoIXRoaXMuX2Zvcm1EYXRhKSB7XG4gICAgdGhpcy5fZm9ybURhdGEgPSBuZXcgRm9ybURhdGEoKTtcbiAgICB0aGlzLl9mb3JtRGF0YS5vbignZXJyb3InLCBlcnIgPT4ge1xuICAgICAgZGVidWcoJ0Zvcm1EYXRhIGVycm9yJywgZXJyKTtcbiAgICAgIGlmICh0aGlzLmNhbGxlZCkge1xuICAgICAgICAvLyBUaGUgcmVxdWVzdCBoYXMgYWxyZWFkeSBmaW5pc2hlZCBhbmQgdGhlIGNhbGxiYWNrIHdhcyBjYWxsZWQuXG4gICAgICAgIC8vIFNpbGVudGx5IGlnbm9yZSB0aGUgZXJyb3IuXG4gICAgICAgIHJldHVybjtcbiAgICAgIH1cblxuICAgICAgdGhpcy5jYWxsYmFjayhlcnIpO1xuICAgICAgdGhpcy5hYm9ydCgpO1xuICAgIH0pO1xuICB9XG5cbiAgcmV0dXJuIHRoaXMuX2Zvcm1EYXRhO1xufTtcblxuLyoqXG4gKiBHZXRzL3NldHMgdGhlIGBBZ2VudGAgdG8gdXNlIGZvciB0aGlzIEhUVFAgcmVxdWVzdC4gVGhlIGRlZmF1bHQgKGlmIHRoaXNcbiAqIGZ1bmN0aW9uIGlzIG5vdCBjYWxsZWQpIGlzIHRvIG9wdCBvdXQgb2YgY29ubmVjdGlvbiBwb29saW5nIChgYWdlbnQ6IGZhbHNlYCkuXG4gKlxuICogQHBhcmFtIHtodHRwLkFnZW50fSBhZ2VudFxuICogQHJldHVybiB7aHR0cC5BZ2VudH1cbiAqIEBhcGkgcHVibGljXG4gKi9cblxuUmVxdWVzdC5wcm90b3R5cGUuYWdlbnQgPSBmdW5jdGlvbihhZ2VudCkge1xuICBpZiAoYXJndW1lbnRzLmxlbmd0aCA9PT0gMCkgcmV0dXJuIHRoaXMuX2FnZW50O1xuICB0aGlzLl9hZ2VudCA9IGFnZW50O1xuICByZXR1cm4gdGhpcztcbn07XG5cbi8qKlxuICogU2V0IF9Db250ZW50LVR5cGVfIHJlc3BvbnNlIGhlYWRlciBwYXNzZWQgdGhyb3VnaCBgbWltZS5nZXRUeXBlKClgLlxuICpcbiAqIEV4YW1wbGVzOlxuICpcbiAqICAgICAgcmVxdWVzdC5wb3N0KCcvJylcbiAqICAgICAgICAudHlwZSgneG1sJylcbiAqICAgICAgICAuc2VuZCh4bWxzdHJpbmcpXG4gKiAgICAgICAgLmVuZChjYWxsYmFjayk7XG4gKlxuICogICAgICByZXF1ZXN0LnBvc3QoJy8nKVxuICogICAgICAgIC50eXBlKCdqc29uJylcbiAqICAgICAgICAuc2VuZChqc29uc3RyaW5nKVxuICogICAgICAgIC5lbmQoY2FsbGJhY2spO1xuICpcbiAqICAgICAgcmVxdWVzdC5wb3N0KCcvJylcbiAqICAgICAgICAudHlwZSgnYXBwbGljYXRpb24vanNvbicpXG4gKiAgICAgICAgLnNlbmQoanNvbnN0cmluZylcbiAqICAgICAgICAuZW5kKGNhbGxiYWNrKTtcbiAqXG4gKiBAcGFyYW0ge1N0cmluZ30gdHlwZVxuICogQHJldHVybiB7UmVxdWVzdH0gZm9yIGNoYWluaW5nXG4gKiBAYXBpIHB1YmxpY1xuICovXG5cblJlcXVlc3QucHJvdG90eXBlLnR5cGUgPSBmdW5jdGlvbih0eXBlKSB7XG4gIHJldHVybiB0aGlzLnNldChcbiAgICAnQ29udGVudC1UeXBlJyxcbiAgICB0eXBlLmluY2x1ZGVzKCcvJykgPyB0eXBlIDogbWltZS5nZXRUeXBlKHR5cGUpXG4gICk7XG59O1xuXG4vKipcbiAqIFNldCBfQWNjZXB0XyByZXNwb25zZSBoZWFkZXIgcGFzc2VkIHRocm91Z2ggYG1pbWUuZ2V0VHlwZSgpYC5cbiAqXG4gKiBFeGFtcGxlczpcbiAqXG4gKiAgICAgIHN1cGVyYWdlbnQudHlwZXMuanNvbiA9ICdhcHBsaWNhdGlvbi9qc29uJztcbiAqXG4gKiAgICAgIHJlcXVlc3QuZ2V0KCcvYWdlbnQnKVxuICogICAgICAgIC5hY2NlcHQoJ2pzb24nKVxuICogICAgICAgIC5lbmQoY2FsbGJhY2spO1xuICpcbiAqICAgICAgcmVxdWVzdC5nZXQoJy9hZ2VudCcpXG4gKiAgICAgICAgLmFjY2VwdCgnYXBwbGljYXRpb24vanNvbicpXG4gKiAgICAgICAgLmVuZChjYWxsYmFjayk7XG4gKlxuICogQHBhcmFtIHtTdHJpbmd9IGFjY2VwdFxuICogQHJldHVybiB7UmVxdWVzdH0gZm9yIGNoYWluaW5nXG4gKiBAYXBpIHB1YmxpY1xuICovXG5cblJlcXVlc3QucHJvdG90eXBlLmFjY2VwdCA9IGZ1bmN0aW9uKHR5cGUpIHtcbiAgcmV0dXJuIHRoaXMuc2V0KCdBY2NlcHQnLCB0eXBlLmluY2x1ZGVzKCcvJykgPyB0eXBlIDogbWltZS5nZXRUeXBlKHR5cGUpKTtcbn07XG5cbi8qKlxuICogQWRkIHF1ZXJ5LXN0cmluZyBgdmFsYC5cbiAqXG4gKiBFeGFtcGxlczpcbiAqXG4gKiAgIHJlcXVlc3QuZ2V0KCcvc2hvZXMnKVxuICogICAgIC5xdWVyeSgnc2l6ZT0xMCcpXG4gKiAgICAgLnF1ZXJ5KHsgY29sb3I6ICdibHVlJyB9KVxuICpcbiAqIEBwYXJhbSB7T2JqZWN0fFN0cmluZ30gdmFsXG4gKiBAcmV0dXJuIHtSZXF1ZXN0fSBmb3IgY2hhaW5pbmdcbiAqIEBhcGkgcHVibGljXG4gKi9cblxuUmVxdWVzdC5wcm90b3R5cGUucXVlcnkgPSBmdW5jdGlvbih2YWwpIHtcbiAgaWYgKHR5cGVvZiB2YWwgPT09ICdzdHJpbmcnKSB7XG4gICAgdGhpcy5fcXVlcnkucHVzaCh2YWwpO1xuICB9IGVsc2Uge1xuICAgIE9iamVjdC5hc3NpZ24odGhpcy5xcywgdmFsKTtcbiAgfVxuXG4gIHJldHVybiB0aGlzO1xufTtcblxuLyoqXG4gKiBXcml0ZSByYXcgYGRhdGFgIC8gYGVuY29kaW5nYCB0byB0aGUgc29ja2V0LlxuICpcbiAqIEBwYXJhbSB7QnVmZmVyfFN0cmluZ30gZGF0YVxuICogQHBhcmFtIHtTdHJpbmd9IGVuY29kaW5nXG4gKiBAcmV0dXJuIHtCb29sZWFufVxuICogQGFwaSBwdWJsaWNcbiAqL1xuXG5SZXF1ZXN0LnByb3RvdHlwZS53cml0ZSA9IGZ1bmN0aW9uKGRhdGEsIGVuY29kaW5nKSB7XG4gIGNvbnN0IHJlcSA9IHRoaXMucmVxdWVzdCgpO1xuICBpZiAoIXRoaXMuX3N0cmVhbVJlcXVlc3QpIHtcbiAgICB0aGlzLl9zdHJlYW1SZXF1ZXN0ID0gdHJ1ZTtcbiAgfVxuXG4gIHJldHVybiByZXEud3JpdGUoZGF0YSwgZW5jb2RpbmcpO1xufTtcblxuLyoqXG4gKiBQaXBlIHRoZSByZXF1ZXN0IGJvZHkgdG8gYHN0cmVhbWAuXG4gKlxuICogQHBhcmFtIHtTdHJlYW19IHN0cmVhbVxuICogQHBhcmFtIHtPYmplY3R9IG9wdGlvbnNcbiAqIEByZXR1cm4ge1N0cmVhbX1cbiAqIEBhcGkgcHVibGljXG4gKi9cblxuUmVxdWVzdC5wcm90b3R5cGUucGlwZSA9IGZ1bmN0aW9uKHN0cmVhbSwgb3B0aW9ucykge1xuICB0aGlzLnBpcGVkID0gdHJ1ZTsgLy8gSEFDSy4uLlxuICB0aGlzLmJ1ZmZlcihmYWxzZSk7XG4gIHRoaXMuZW5kKCk7XG4gIHJldHVybiB0aGlzLl9waXBlQ29udGludWUoc3RyZWFtLCBvcHRpb25zKTtcbn07XG5cblJlcXVlc3QucHJvdG90eXBlLl9waXBlQ29udGludWUgPSBmdW5jdGlvbihzdHJlYW0sIG9wdGlvbnMpIHtcbiAgdGhpcy5yZXEub25jZSgncmVzcG9uc2UnLCByZXMgPT4ge1xuICAgIC8vIHJlZGlyZWN0XG4gICAgaWYgKFxuICAgICAgaXNSZWRpcmVjdChyZXMuc3RhdHVzQ29kZSkgJiZcbiAgICAgIHRoaXMuX3JlZGlyZWN0cysrICE9PSB0aGlzLl9tYXhSZWRpcmVjdHNcbiAgICApIHtcbiAgICAgIHJldHVybiB0aGlzLl9yZWRpcmVjdChyZXMpID09PSB0aGlzXG4gICAgICAgID8gdGhpcy5fcGlwZUNvbnRpbnVlKHN0cmVhbSwgb3B0aW9ucylcbiAgICAgICAgOiB1bmRlZmluZWQ7XG4gICAgfVxuXG4gICAgdGhpcy5yZXMgPSByZXM7XG4gICAgdGhpcy5fZW1pdFJlc3BvbnNlKCk7XG4gICAgaWYgKHRoaXMuX2Fib3J0ZWQpIHJldHVybjtcblxuICAgIGlmICh0aGlzLl9zaG91bGRVbnppcChyZXMpKSB7XG4gICAgICBjb25zdCB1bnppcE9iaiA9IHpsaWIuY3JlYXRlVW56aXAoKTtcbiAgICAgIHVuemlwT2JqLm9uKCdlcnJvcicsIGVyciA9PiB7XG4gICAgICAgIGlmIChlcnIgJiYgZXJyLmNvZGUgPT09ICdaX0JVRl9FUlJPUicpIHtcbiAgICAgICAgICAvLyB1bmV4cGVjdGVkIGVuZCBvZiBmaWxlIGlzIGlnbm9yZWQgYnkgYnJvd3NlcnMgYW5kIGN1cmxcbiAgICAgICAgICBzdHJlYW0uZW1pdCgnZW5kJyk7XG4gICAgICAgICAgcmV0dXJuO1xuICAgICAgICB9XG5cbiAgICAgICAgc3RyZWFtLmVtaXQoJ2Vycm9yJywgZXJyKTtcbiAgICAgIH0pO1xuICAgICAgcmVzLnBpcGUodW56aXBPYmopLnBpcGUoc3RyZWFtLCBvcHRpb25zKTtcbiAgICB9IGVsc2Uge1xuICAgICAgcmVzLnBpcGUoc3RyZWFtLCBvcHRpb25zKTtcbiAgICB9XG5cbiAgICByZXMub25jZSgnZW5kJywgKCkgPT4ge1xuICAgICAgdGhpcy5lbWl0KCdlbmQnKTtcbiAgICB9KTtcbiAgfSk7XG4gIHJldHVybiBzdHJlYW07XG59O1xuXG4vKipcbiAqIEVuYWJsZSAvIGRpc2FibGUgYnVmZmVyaW5nLlxuICpcbiAqIEByZXR1cm4ge0Jvb2xlYW59IFt2YWxdXG4gKiBAcmV0dXJuIHtSZXF1ZXN0fSBmb3IgY2hhaW5pbmdcbiAqIEBhcGkgcHVibGljXG4gKi9cblxuUmVxdWVzdC5wcm90b3R5cGUuYnVmZmVyID0gZnVuY3Rpb24odmFsKSB7XG4gIHRoaXMuX2J1ZmZlciA9IHZhbCAhPT0gZmFsc2U7XG4gIHJldHVybiB0aGlzO1xufTtcblxuLyoqXG4gKiBSZWRpcmVjdCB0byBgdXJsXG4gKlxuICogQHBhcmFtIHtJbmNvbWluZ01lc3NhZ2V9IHJlc1xuICogQHJldHVybiB7UmVxdWVzdH0gZm9yIGNoYWluaW5nXG4gKiBAYXBpIHByaXZhdGVcbiAqL1xuXG5SZXF1ZXN0LnByb3RvdHlwZS5fcmVkaXJlY3QgPSBmdW5jdGlvbihyZXMpIHtcbiAgbGV0IHVybCA9IHJlcy5oZWFkZXJzLmxvY2F0aW9uO1xuICBpZiAoIXVybCkge1xuICAgIHJldHVybiB0aGlzLmNhbGxiYWNrKG5ldyBFcnJvcignTm8gbG9jYXRpb24gaGVhZGVyIGZvciByZWRpcmVjdCcpLCByZXMpO1xuICB9XG5cbiAgZGVidWcoJ3JlZGlyZWN0ICVzIC0+ICVzJywgdGhpcy51cmwsIHVybCk7XG5cbiAgLy8gbG9jYXRpb25cbiAgdXJsID0gcmVzb2x2ZSh0aGlzLnVybCwgdXJsKTtcblxuICAvLyBlbnN1cmUgdGhlIHJlc3BvbnNlIGlzIGJlaW5nIGNvbnN1bWVkXG4gIC8vIHRoaXMgaXMgcmVxdWlyZWQgZm9yIE5vZGUgdjAuMTArXG4gIHJlcy5yZXN1bWUoKTtcblxuICBsZXQgaGVhZGVycyA9IHRoaXMucmVxLmdldEhlYWRlcnMgPyB0aGlzLnJlcS5nZXRIZWFkZXJzKCkgOiB0aGlzLnJlcS5faGVhZGVycztcblxuICBjb25zdCBjaGFuZ2VzT3JpZ2luID0gcGFyc2UodXJsKS5ob3N0ICE9PSBwYXJzZSh0aGlzLnVybCkuaG9zdDtcblxuICAvLyBpbXBsZW1lbnRhdGlvbiBvZiAzMDIgZm9sbG93aW5nIGRlZmFjdG8gc3RhbmRhcmRcbiAgaWYgKHJlcy5zdGF0dXNDb2RlID09PSAzMDEgfHwgcmVzLnN0YXR1c0NvZGUgPT09IDMwMikge1xuICAgIC8vIHN0cmlwIENvbnRlbnQtKiByZWxhdGVkIGZpZWxkc1xuICAgIC8vIGluIGNhc2Ugb2YgUE9TVCBldGNcbiAgICBoZWFkZXJzID0gdXRpbHMuY2xlYW5IZWFkZXIoaGVhZGVycywgY2hhbmdlc09yaWdpbik7XG5cbiAgICAvLyBmb3JjZSBHRVRcbiAgICB0aGlzLm1ldGhvZCA9IHRoaXMubWV0aG9kID09PSAnSEVBRCcgPyAnSEVBRCcgOiAnR0VUJztcblxuICAgIC8vIGNsZWFyIGRhdGFcbiAgICB0aGlzLl9kYXRhID0gbnVsbDtcbiAgfVxuXG4gIC8vIDMwMyBpcyBhbHdheXMgR0VUXG4gIGlmIChyZXMuc3RhdHVzQ29kZSA9PT0gMzAzKSB7XG4gICAgLy8gc3RyaXAgQ29udGVudC0qIHJlbGF0ZWQgZmllbGRzXG4gICAgLy8gaW4gY2FzZSBvZiBQT1NUIGV0Y1xuICAgIGhlYWRlcnMgPSB1dGlscy5jbGVhbkhlYWRlcihoZWFkZXJzLCBjaGFuZ2VzT3JpZ2luKTtcblxuICAgIC8vIGZvcmNlIG1ldGhvZFxuICAgIHRoaXMubWV0aG9kID0gJ0dFVCc7XG5cbiAgICAvLyBjbGVhciBkYXRhXG4gICAgdGhpcy5fZGF0YSA9IG51bGw7XG4gIH1cblxuICAvLyAzMDcgcHJlc2VydmVzIG1ldGhvZFxuICAvLyAzMDggcHJlc2VydmVzIG1ldGhvZFxuICBkZWxldGUgaGVhZGVycy5ob3N0O1xuXG4gIGRlbGV0ZSB0aGlzLnJlcTtcbiAgZGVsZXRlIHRoaXMuX2Zvcm1EYXRhO1xuXG4gIC8vIHJlbW92ZSBhbGwgYWRkIGhlYWRlciBleGNlcHQgVXNlci1BZ2VudFxuICBfaW5pdEhlYWRlcnModGhpcyk7XG5cbiAgLy8gcmVkaXJlY3RcbiAgdGhpcy5fZW5kQ2FsbGVkID0gZmFsc2U7XG4gIHRoaXMudXJsID0gdXJsO1xuICB0aGlzLnFzID0ge307XG4gIHRoaXMuX3F1ZXJ5Lmxlbmd0aCA9IDA7XG4gIHRoaXMuc2V0KGhlYWRlcnMpO1xuICB0aGlzLmVtaXQoJ3JlZGlyZWN0JywgcmVzKTtcbiAgdGhpcy5fcmVkaXJlY3RMaXN0LnB1c2godGhpcy51cmwpO1xuICB0aGlzLmVuZCh0aGlzLl9jYWxsYmFjayk7XG4gIHJldHVybiB0aGlzO1xufTtcblxuLyoqXG4gKiBTZXQgQXV0aG9yaXphdGlvbiBmaWVsZCB2YWx1ZSB3aXRoIGB1c2VyYCBhbmQgYHBhc3NgLlxuICpcbiAqIEV4YW1wbGVzOlxuICpcbiAqICAgLmF1dGgoJ3RvYmknLCAnbGVhcm5ib29zdCcpXG4gKiAgIC5hdXRoKCd0b2JpOmxlYXJuYm9vc3QnKVxuICogICAuYXV0aCgndG9iaScpXG4gKiAgIC5hdXRoKGFjY2Vzc1Rva2VuLCB7IHR5cGU6ICdiZWFyZXInIH0pXG4gKlxuICogQHBhcmFtIHtTdHJpbmd9IHVzZXJcbiAqIEBwYXJhbSB7U3RyaW5nfSBbcGFzc11cbiAqIEBwYXJhbSB7T2JqZWN0fSBbb3B0aW9uc10gb3B0aW9ucyB3aXRoIGF1dGhvcml6YXRpb24gdHlwZSAnYmFzaWMnIG9yICdiZWFyZXInICgnYmFzaWMnIGlzIGRlZmF1bHQpXG4gKiBAcmV0dXJuIHtSZXF1ZXN0fSBmb3IgY2hhaW5pbmdcbiAqIEBhcGkgcHVibGljXG4gKi9cblxuUmVxdWVzdC5wcm90b3R5cGUuYXV0aCA9IGZ1bmN0aW9uKHVzZXIsIHBhc3MsIG9wdGlvbnMpIHtcbiAgaWYgKGFyZ3VtZW50cy5sZW5ndGggPT09IDEpIHBhc3MgPSAnJztcbiAgaWYgKHR5cGVvZiBwYXNzID09PSAnb2JqZWN0JyAmJiBwYXNzICE9PSBudWxsKSB7XG4gICAgLy8gcGFzcyBpcyBvcHRpb25hbCBhbmQgY2FuIGJlIHJlcGxhY2VkIHdpdGggb3B0aW9uc1xuICAgIG9wdGlvbnMgPSBwYXNzO1xuICAgIHBhc3MgPSAnJztcbiAgfVxuXG4gIGlmICghb3B0aW9ucykge1xuICAgIG9wdGlvbnMgPSB7IHR5cGU6ICdiYXNpYycgfTtcbiAgfVxuXG4gIGNvbnN0IGVuY29kZXIgPSBzdHJpbmcgPT4gQnVmZmVyLmZyb20oc3RyaW5nKS50b1N0cmluZygnYmFzZTY0Jyk7XG5cbiAgcmV0dXJuIHRoaXMuX2F1dGgodXNlciwgcGFzcywgb3B0aW9ucywgZW5jb2Rlcik7XG59O1xuXG4vKipcbiAqIFNldCB0aGUgY2VydGlmaWNhdGUgYXV0aG9yaXR5IG9wdGlvbiBmb3IgaHR0cHMgcmVxdWVzdC5cbiAqXG4gKiBAcGFyYW0ge0J1ZmZlciB8IEFycmF5fSBjZXJ0XG4gKiBAcmV0dXJuIHtSZXF1ZXN0fSBmb3IgY2hhaW5pbmdcbiAqIEBhcGkgcHVibGljXG4gKi9cblxuUmVxdWVzdC5wcm90b3R5cGUuY2EgPSBmdW5jdGlvbihjZXJ0KSB7XG4gIHRoaXMuX2NhID0gY2VydDtcbiAgcmV0dXJuIHRoaXM7XG59O1xuXG4vKipcbiAqIFNldCB0aGUgY2xpZW50IGNlcnRpZmljYXRlIGtleSBvcHRpb24gZm9yIGh0dHBzIHJlcXVlc3QuXG4gKlxuICogQHBhcmFtIHtCdWZmZXIgfCBTdHJpbmd9IGNlcnRcbiAqIEByZXR1cm4ge1JlcXVlc3R9IGZvciBjaGFpbmluZ1xuICogQGFwaSBwdWJsaWNcbiAqL1xuXG5SZXF1ZXN0LnByb3RvdHlwZS5rZXkgPSBmdW5jdGlvbihjZXJ0KSB7XG4gIHRoaXMuX2tleSA9IGNlcnQ7XG4gIHJldHVybiB0aGlzO1xufTtcblxuLyoqXG4gKiBTZXQgdGhlIGtleSwgY2VydGlmaWNhdGUsIGFuZCBDQSBjZXJ0cyBvZiB0aGUgY2xpZW50IGluIFBGWCBvciBQS0NTMTIgZm9ybWF0LlxuICpcbiAqIEBwYXJhbSB7QnVmZmVyIHwgU3RyaW5nfSBjZXJ0XG4gKiBAcmV0dXJuIHtSZXF1ZXN0fSBmb3IgY2hhaW5pbmdcbiAqIEBhcGkgcHVibGljXG4gKi9cblxuUmVxdWVzdC5wcm90b3R5cGUucGZ4ID0gZnVuY3Rpb24oY2VydCkge1xuICBpZiAodHlwZW9mIGNlcnQgPT09ICdvYmplY3QnICYmICFCdWZmZXIuaXNCdWZmZXIoY2VydCkpIHtcbiAgICB0aGlzLl9wZnggPSBjZXJ0LnBmeDtcbiAgICB0aGlzLl9wYXNzcGhyYXNlID0gY2VydC5wYXNzcGhyYXNlO1xuICB9IGVsc2Uge1xuICAgIHRoaXMuX3BmeCA9IGNlcnQ7XG4gIH1cblxuICByZXR1cm4gdGhpcztcbn07XG5cbi8qKlxuICogU2V0IHRoZSBjbGllbnQgY2VydGlmaWNhdGUgb3B0aW9uIGZvciBodHRwcyByZXF1ZXN0LlxuICpcbiAqIEBwYXJhbSB7QnVmZmVyIHwgU3RyaW5nfSBjZXJ0XG4gKiBAcmV0dXJuIHtSZXF1ZXN0fSBmb3IgY2hhaW5pbmdcbiAqIEBhcGkgcHVibGljXG4gKi9cblxuUmVxdWVzdC5wcm90b3R5cGUuY2VydCA9IGZ1bmN0aW9uKGNlcnQpIHtcbiAgdGhpcy5fY2VydCA9IGNlcnQ7XG4gIHJldHVybiB0aGlzO1xufTtcblxuLyoqXG4gKiBEbyBub3QgcmVqZWN0IGV4cGlyZWQgb3IgaW52YWxpZCBUTFMgY2VydHMuXG4gKiBzZXRzIGByZWplY3RVbmF1dGhvcml6ZWQ9dHJ1ZWAuIEJlIHdhcm5lZCB0aGF0IHRoaXMgYWxsb3dzIE1JVE0gYXR0YWNrcy5cbiAqXG4gKiBAcmV0dXJuIHtSZXF1ZXN0fSBmb3IgY2hhaW5pbmdcbiAqIEBhcGkgcHVibGljXG4gKi9cblxuUmVxdWVzdC5wcm90b3R5cGUuZGlzYWJsZVRMU0NlcnRzID0gZnVuY3Rpb24oKSB7XG4gIHRoaXMuX2Rpc2FibGVUTFNDZXJ0cyA9IHRydWU7XG4gIHJldHVybiB0aGlzO1xufTtcblxuLyoqXG4gKiBSZXR1cm4gYW4gaHR0cFtzXSByZXF1ZXN0LlxuICpcbiAqIEByZXR1cm4ge091dGdvaW5nTWVzc2FnZX1cbiAqIEBhcGkgcHJpdmF0ZVxuICovXG5cbi8vIGVzbGludC1kaXNhYmxlLW5leHQtbGluZSBjb21wbGV4aXR5XG5SZXF1ZXN0LnByb3RvdHlwZS5yZXF1ZXN0ID0gZnVuY3Rpb24oKSB7XG4gIGlmICh0aGlzLnJlcSkgcmV0dXJuIHRoaXMucmVxO1xuXG4gIGNvbnN0IG9wdGlvbnMgPSB7fTtcblxuICB0cnkge1xuICAgIGNvbnN0IHF1ZXJ5ID0gcXMuc3RyaW5naWZ5KHRoaXMucXMsIHtcbiAgICAgIGluZGljZXM6IGZhbHNlLFxuICAgICAgc3RyaWN0TnVsbEhhbmRsaW5nOiB0cnVlXG4gICAgfSk7XG4gICAgaWYgKHF1ZXJ5KSB7XG4gICAgICB0aGlzLnFzID0ge307XG4gICAgICB0aGlzLl9xdWVyeS5wdXNoKHF1ZXJ5KTtcbiAgICB9XG5cbiAgICB0aGlzLl9maW5hbGl6ZVF1ZXJ5U3RyaW5nKCk7XG4gIH0gY2F0Y2ggKGVycikge1xuICAgIHJldHVybiB0aGlzLmVtaXQoJ2Vycm9yJywgZXJyKTtcbiAgfVxuXG4gIGxldCB7IHVybCB9ID0gdGhpcztcbiAgY29uc3QgcmV0cmllcyA9IHRoaXMuX3JldHJpZXM7XG5cbiAgLy8gQ2FwdHVyZSBiYWNrdGlja3MgYXMtaXMgZnJvbSB0aGUgZmluYWwgcXVlcnkgc3RyaW5nIGJ1aWx0IGFib3ZlLlxuICAvLyBOb3RlOiB0aGlzJ2xsIG9ubHkgZmluZCBiYWNrdGlja3MgZW50ZXJlZCBpbiByZXEucXVlcnkoU3RyaW5nKVxuICAvLyBjYWxscywgYmVjYXVzZSBxcy5zdHJpbmdpZnkgdW5jb25kaXRpb25hbGx5IGVuY29kZXMgYmFja3RpY2tzLlxuICBsZXQgcXVlcnlTdHJpbmdCYWNrdGlja3M7XG4gIGlmICh1cmwuaW5jbHVkZXMoJ2AnKSkge1xuICAgIGNvbnN0IHF1ZXJ5U3RhcnRJbmRleCA9IHVybC5pbmRleE9mKCc/Jyk7XG5cbiAgICBpZiAocXVlcnlTdGFydEluZGV4ICE9PSAtMSkge1xuICAgICAgY29uc3QgcXVlcnlTdHJpbmcgPSB1cmwuc2xpY2UocXVlcnlTdGFydEluZGV4ICsgMSk7XG4gICAgICBxdWVyeVN0cmluZ0JhY2t0aWNrcyA9IHF1ZXJ5U3RyaW5nLm1hdGNoKC9gfCU2MC9nKTtcbiAgICB9XG4gIH1cblxuICAvLyBkZWZhdWx0IHRvIGh0dHA6Ly9cbiAgaWYgKHVybC5pbmRleE9mKCdodHRwJykgIT09IDApIHVybCA9IGBodHRwOi8vJHt1cmx9YDtcbiAgdXJsID0gcGFyc2UodXJsKTtcblxuICAvLyBTZWUgaHR0cHM6Ly9naXRodWIuY29tL3Zpc2lvbm1lZGlhL3N1cGVyYWdlbnQvaXNzdWVzLzEzNjdcbiAgaWYgKHF1ZXJ5U3RyaW5nQmFja3RpY2tzKSB7XG4gICAgbGV0IGkgPSAwO1xuICAgIHVybC5xdWVyeSA9IHVybC5xdWVyeS5yZXBsYWNlKC8lNjAvZywgKCkgPT4gcXVlcnlTdHJpbmdCYWNrdGlja3NbaSsrXSk7XG4gICAgdXJsLnNlYXJjaCA9IGA/JHt1cmwucXVlcnl9YDtcbiAgICB1cmwucGF0aCA9IHVybC5wYXRobmFtZSArIHVybC5zZWFyY2g7XG4gIH1cblxuICAvLyBzdXBwb3J0IHVuaXggc29ja2V0c1xuICBpZiAoL15odHRwcz9cXCt1bml4Oi8udGVzdCh1cmwucHJvdG9jb2wpID09PSB0cnVlKSB7XG4gICAgLy8gZ2V0IHRoZSBwcm90b2NvbFxuICAgIHVybC5wcm90b2NvbCA9IGAke3VybC5wcm90b2NvbC5zcGxpdCgnKycpWzBdfTpgO1xuXG4gICAgLy8gZ2V0IHRoZSBzb2NrZXQsIHBhdGhcbiAgICBjb25zdCB1bml4UGFydHMgPSB1cmwucGF0aC5tYXRjaCgvXihbXi9dKykoLispJC8pO1xuICAgIG9wdGlvbnMuc29ja2V0UGF0aCA9IHVuaXhQYXJ0c1sxXS5yZXBsYWNlKC8lMkYvZywgJy8nKTtcbiAgICB1cmwucGF0aCA9IHVuaXhQYXJ0c1syXTtcbiAgfVxuXG4gIC8vIE92ZXJyaWRlIElQIGFkZHJlc3Mgb2YgYSBob3N0bmFtZVxuICBpZiAodGhpcy5fY29ubmVjdE92ZXJyaWRlKSB7XG4gICAgY29uc3QgeyBob3N0bmFtZSB9ID0gdXJsO1xuICAgIGNvbnN0IG1hdGNoID1cbiAgICAgIGhvc3RuYW1lIGluIHRoaXMuX2Nvbm5lY3RPdmVycmlkZVxuICAgICAgICA/IHRoaXMuX2Nvbm5lY3RPdmVycmlkZVtob3N0bmFtZV1cbiAgICAgICAgOiB0aGlzLl9jb25uZWN0T3ZlcnJpZGVbJyonXTtcbiAgICBpZiAobWF0Y2gpIHtcbiAgICAgIC8vIGJhY2t1cCB0aGUgcmVhbCBob3N0XG4gICAgICBpZiAoIXRoaXMuX2hlYWRlci5ob3N0KSB7XG4gICAgICAgIHRoaXMuc2V0KCdob3N0JywgdXJsLmhvc3QpO1xuICAgICAgfVxuXG4gICAgICBsZXQgbmV3SG9zdDtcbiAgICAgIGxldCBuZXdQb3J0O1xuXG4gICAgICBpZiAodHlwZW9mIG1hdGNoID09PSAnb2JqZWN0Jykge1xuICAgICAgICBuZXdIb3N0ID0gbWF0Y2guaG9zdDtcbiAgICAgICAgbmV3UG9ydCA9IG1hdGNoLnBvcnQ7XG4gICAgICB9IGVsc2Uge1xuICAgICAgICBuZXdIb3N0ID0gbWF0Y2g7XG4gICAgICAgIG5ld1BvcnQgPSB1cmwucG9ydDtcbiAgICAgIH1cblxuICAgICAgLy8gd3JhcCBbaXB2Nl1cbiAgICAgIHVybC5ob3N0ID0gLzovLnRlc3QobmV3SG9zdCkgPyBgWyR7bmV3SG9zdH1dYCA6IG5ld0hvc3Q7XG4gICAgICBpZiAobmV3UG9ydCkge1xuICAgICAgICB1cmwuaG9zdCArPSBgOiR7bmV3UG9ydH1gO1xuICAgICAgICB1cmwucG9ydCA9IG5ld1BvcnQ7XG4gICAgICB9XG5cbiAgICAgIHVybC5ob3N0bmFtZSA9IG5ld0hvc3Q7XG4gICAgfVxuICB9XG5cbiAgLy8gb3B0aW9uc1xuICBvcHRpb25zLm1ldGhvZCA9IHRoaXMubWV0aG9kO1xuICBvcHRpb25zLnBvcnQgPSB1cmwucG9ydDtcbiAgb3B0aW9ucy5wYXRoID0gdXJsLnBhdGg7XG4gIG9wdGlvbnMuaG9zdCA9IHVybC5ob3N0bmFtZTtcbiAgb3B0aW9ucy5jYSA9IHRoaXMuX2NhO1xuICBvcHRpb25zLmtleSA9IHRoaXMuX2tleTtcbiAgb3B0aW9ucy5wZnggPSB0aGlzLl9wZng7XG4gIG9wdGlvbnMuY2VydCA9IHRoaXMuX2NlcnQ7XG4gIG9wdGlvbnMucGFzc3BocmFzZSA9IHRoaXMuX3Bhc3NwaHJhc2U7XG4gIG9wdGlvbnMuYWdlbnQgPSB0aGlzLl9hZ2VudDtcbiAgb3B0aW9ucy5yZWplY3RVbmF1dGhvcml6ZWQgPVxuICAgIHR5cGVvZiB0aGlzLl9kaXNhYmxlVExTQ2VydHMgPT09ICdib29sZWFuJ1xuICAgICAgPyAhdGhpcy5fZGlzYWJsZVRMU0NlcnRzXG4gICAgICA6IHByb2Nlc3MuZW52Lk5PREVfVExTX1JFSkVDVF9VTkFVVEhPUklaRUQgIT09ICcwJztcblxuICAvLyBBbGxvd3MgcmVxdWVzdC5nZXQoJ2h0dHBzOi8vMS4yLjMuNC8nKS5zZXQoJ0hvc3QnLCAnZXhhbXBsZS5jb20nKVxuICBpZiAodGhpcy5faGVhZGVyLmhvc3QpIHtcbiAgICBvcHRpb25zLnNlcnZlcm5hbWUgPSB0aGlzLl9oZWFkZXIuaG9zdC5yZXBsYWNlKC86XFxkKyQvLCAnJyk7XG4gIH1cblxuICBpZiAoXG4gICAgdGhpcy5fdHJ1c3RMb2NhbGhvc3QgJiZcbiAgICAvXig/OmxvY2FsaG9zdHwxMjdcXC4wXFwuMFxcLlxcZCt8KDAqOikrOjAqMSkkLy50ZXN0KHVybC5ob3N0bmFtZSlcbiAgKSB7XG4gICAgb3B0aW9ucy5yZWplY3RVbmF1dGhvcml6ZWQgPSBmYWxzZTtcbiAgfVxuXG4gIC8vIGluaXRpYXRlIHJlcXVlc3RcbiAgY29uc3QgbW9kID0gdGhpcy5fZW5hYmxlSHR0cDJcbiAgICA/IGV4cG9ydHMucHJvdG9jb2xzWydodHRwMjonXS5zZXRQcm90b2NvbCh1cmwucHJvdG9jb2wpXG4gICAgOiBleHBvcnRzLnByb3RvY29sc1t1cmwucHJvdG9jb2xdO1xuXG4gIC8vIHJlcXVlc3RcbiAgdGhpcy5yZXEgPSBtb2QucmVxdWVzdChvcHRpb25zKTtcbiAgY29uc3QgeyByZXEgfSA9IHRoaXM7XG5cbiAgLy8gc2V0IHRjcCBubyBkZWxheVxuICByZXEuc2V0Tm9EZWxheSh0cnVlKTtcblxuICBpZiAob3B0aW9ucy5tZXRob2QgIT09ICdIRUFEJykge1xuICAgIHJlcS5zZXRIZWFkZXIoJ0FjY2VwdC1FbmNvZGluZycsICdnemlwLCBkZWZsYXRlJyk7XG4gIH1cblxuICB0aGlzLnByb3RvY29sID0gdXJsLnByb3RvY29sO1xuICB0aGlzLmhvc3QgPSB1cmwuaG9zdDtcblxuICAvLyBleHBvc2UgZXZlbnRzXG4gIHJlcS5vbmNlKCdkcmFpbicsICgpID0+IHtcbiAgICB0aGlzLmVtaXQoJ2RyYWluJyk7XG4gIH0pO1xuXG4gIHJlcS5vbignZXJyb3InLCBlcnIgPT4ge1xuICAgIC8vIGZsYWcgYWJvcnRpb24gaGVyZSBmb3Igb3V0IHRpbWVvdXRzXG4gICAgLy8gYmVjYXVzZSBub2RlIHdpbGwgZW1pdCBhIGZhdXgtZXJyb3IgXCJzb2NrZXQgaGFuZyB1cFwiXG4gICAgLy8gd2hlbiByZXF1ZXN0IGlzIGFib3J0ZWQgYmVmb3JlIGEgY29ubmVjdGlvbiBpcyBtYWRlXG4gICAgaWYgKHRoaXMuX2Fib3J0ZWQpIHJldHVybjtcbiAgICAvLyBpZiBub3QgdGhlIHNhbWUsIHdlIGFyZSBpbiB0aGUgKipvbGQqKiAoY2FuY2VsbGVkKSByZXF1ZXN0LFxuICAgIC8vIHNvIG5lZWQgdG8gY29udGludWUgKHNhbWUgYXMgZm9yIGFib3ZlKVxuICAgIGlmICh0aGlzLl9yZXRyaWVzICE9PSByZXRyaWVzKSByZXR1cm47XG4gICAgLy8gaWYgd2UndmUgcmVjZWl2ZWQgYSByZXNwb25zZSB0aGVuIHdlIGRvbid0IHdhbnQgdG8gbGV0XG4gICAgLy8gYW4gZXJyb3IgaW4gdGhlIHJlcXVlc3QgYmxvdyB1cCB0aGUgcmVzcG9uc2VcbiAgICBpZiAodGhpcy5yZXNwb25zZSkgcmV0dXJuO1xuICAgIHRoaXMuY2FsbGJhY2soZXJyKTtcbiAgfSk7XG5cbiAgLy8gYXV0aFxuICBpZiAodXJsLmF1dGgpIHtcbiAgICBjb25zdCBhdXRoID0gdXJsLmF1dGguc3BsaXQoJzonKTtcbiAgICB0aGlzLmF1dGgoYXV0aFswXSwgYXV0aFsxXSk7XG4gIH1cblxuICBpZiAodGhpcy51c2VybmFtZSAmJiB0aGlzLnBhc3N3b3JkKSB7XG4gICAgdGhpcy5hdXRoKHRoaXMudXNlcm5hbWUsIHRoaXMucGFzc3dvcmQpO1xuICB9XG5cbiAgZm9yIChjb25zdCBrZXkgaW4gdGhpcy5oZWFkZXIpIHtcbiAgICBpZiAoT2JqZWN0LnByb3RvdHlwZS5oYXNPd25Qcm9wZXJ0eS5jYWxsKHRoaXMuaGVhZGVyLCBrZXkpKVxuICAgICAgcmVxLnNldEhlYWRlcihrZXksIHRoaXMuaGVhZGVyW2tleV0pO1xuICB9XG5cbiAgLy8gYWRkIGNvb2tpZXNcbiAgaWYgKHRoaXMuY29va2llcykge1xuICAgIGlmIChPYmplY3QucHJvdG90eXBlLmhhc093blByb3BlcnR5LmNhbGwodGhpcy5faGVhZGVyLCAnY29va2llJykpIHtcbiAgICAgIC8vIG1lcmdlXG4gICAgICBjb25zdCB0bXBKYXIgPSBuZXcgQ29va2llSmFyLkNvb2tpZUphcigpO1xuICAgICAgdG1wSmFyLnNldENvb2tpZXModGhpcy5faGVhZGVyLmNvb2tpZS5zcGxpdCgnOycpKTtcbiAgICAgIHRtcEphci5zZXRDb29raWVzKHRoaXMuY29va2llcy5zcGxpdCgnOycpKTtcbiAgICAgIHJlcS5zZXRIZWFkZXIoXG4gICAgICAgICdDb29raWUnLFxuICAgICAgICB0bXBKYXIuZ2V0Q29va2llcyhDb29raWVKYXIuQ29va2llQWNjZXNzSW5mby5BbGwpLnRvVmFsdWVTdHJpbmcoKVxuICAgICAgKTtcbiAgICB9IGVsc2Uge1xuICAgICAgcmVxLnNldEhlYWRlcignQ29va2llJywgdGhpcy5jb29raWVzKTtcbiAgICB9XG4gIH1cblxuICByZXR1cm4gcmVxO1xufTtcblxuLyoqXG4gKiBJbnZva2UgdGhlIGNhbGxiYWNrIHdpdGggYGVycmAgYW5kIGByZXNgXG4gKiBhbmQgaGFuZGxlIGFyaXR5IGNoZWNrLlxuICpcbiAqIEBwYXJhbSB7RXJyb3J9IGVyclxuICogQHBhcmFtIHtSZXNwb25zZX0gcmVzXG4gKiBAYXBpIHByaXZhdGVcbiAqL1xuXG5SZXF1ZXN0LnByb3RvdHlwZS5jYWxsYmFjayA9IGZ1bmN0aW9uKGVyciwgcmVzKSB7XG4gIGlmICh0aGlzLl9zaG91bGRSZXRyeShlcnIsIHJlcykpIHtcbiAgICByZXR1cm4gdGhpcy5fcmV0cnkoKTtcbiAgfVxuXG4gIC8vIEF2b2lkIHRoZSBlcnJvciB3aGljaCBpcyBlbWl0dGVkIGZyb20gJ3NvY2tldCBoYW5nIHVwJyB0byBjYXVzZSB0aGUgZm4gdW5kZWZpbmVkIGVycm9yIG9uIEpTIHJ1bnRpbWUuXG4gIGNvbnN0IGZuID0gdGhpcy5fY2FsbGJhY2sgfHwgbm9vcDtcbiAgdGhpcy5jbGVhclRpbWVvdXQoKTtcbiAgaWYgKHRoaXMuY2FsbGVkKSByZXR1cm4gY29uc29sZS53YXJuKCdzdXBlcmFnZW50OiBkb3VibGUgY2FsbGJhY2sgYnVnJyk7XG4gIHRoaXMuY2FsbGVkID0gdHJ1ZTtcblxuICBpZiAoIWVycikge1xuICAgIHRyeSB7XG4gICAgICBpZiAoIXRoaXMuX2lzUmVzcG9uc2VPSyhyZXMpKSB7XG4gICAgICAgIGxldCBtc2cgPSAnVW5zdWNjZXNzZnVsIEhUVFAgcmVzcG9uc2UnO1xuICAgICAgICBpZiAocmVzKSB7XG4gICAgICAgICAgbXNnID0gaHR0cC5TVEFUVVNfQ09ERVNbcmVzLnN0YXR1c10gfHwgbXNnO1xuICAgICAgICB9XG5cbiAgICAgICAgZXJyID0gbmV3IEVycm9yKG1zZyk7XG4gICAgICAgIGVyci5zdGF0dXMgPSByZXMgPyByZXMuc3RhdHVzIDogdW5kZWZpbmVkO1xuICAgICAgfVxuICAgIH0gY2F0Y2ggKGVycl8pIHtcbiAgICAgIGVyciA9IGVycl87XG4gICAgfVxuICB9XG5cbiAgLy8gSXQncyBpbXBvcnRhbnQgdGhhdCB0aGUgY2FsbGJhY2sgaXMgY2FsbGVkIG91dHNpZGUgdHJ5L2NhdGNoXG4gIC8vIHRvIGF2b2lkIGRvdWJsZSBjYWxsYmFja1xuICBpZiAoIWVycikge1xuICAgIHJldHVybiBmbihudWxsLCByZXMpO1xuICB9XG5cbiAgZXJyLnJlc3BvbnNlID0gcmVzO1xuICBpZiAodGhpcy5fbWF4UmV0cmllcykgZXJyLnJldHJpZXMgPSB0aGlzLl9yZXRyaWVzIC0gMTtcblxuICAvLyBvbmx5IGVtaXQgZXJyb3IgZXZlbnQgaWYgdGhlcmUgaXMgYSBsaXN0ZW5lclxuICAvLyBvdGhlcndpc2Ugd2UgYXNzdW1lIHRoZSBjYWxsYmFjayB0byBgLmVuZCgpYCB3aWxsIGdldCB0aGUgZXJyb3JcbiAgaWYgKGVyciAmJiB0aGlzLmxpc3RlbmVycygnZXJyb3InKS5sZW5ndGggPiAwKSB7XG4gICAgdGhpcy5lbWl0KCdlcnJvcicsIGVycik7XG4gIH1cblxuICBmbihlcnIsIHJlcyk7XG59O1xuXG4vKipcbiAqIENoZWNrIGlmIGBvYmpgIGlzIGEgaG9zdCBvYmplY3QsXG4gKlxuICogQHBhcmFtIHtPYmplY3R9IG9iaiBob3N0IG9iamVjdFxuICogQHJldHVybiB7Qm9vbGVhbn0gaXMgYSBob3N0IG9iamVjdFxuICogQGFwaSBwcml2YXRlXG4gKi9cblJlcXVlc3QucHJvdG90eXBlLl9pc0hvc3QgPSBmdW5jdGlvbihvYmopIHtcbiAgcmV0dXJuIChcbiAgICBCdWZmZXIuaXNCdWZmZXIob2JqKSB8fCBvYmogaW5zdGFuY2VvZiBTdHJlYW0gfHwgb2JqIGluc3RhbmNlb2YgRm9ybURhdGFcbiAgKTtcbn07XG5cbi8qKlxuICogSW5pdGlhdGUgcmVxdWVzdCwgaW52b2tpbmcgY2FsbGJhY2sgYGZuKGVyciwgcmVzKWBcbiAqIHdpdGggYW4gaW5zdGFuY2VvZiBgUmVzcG9uc2VgLlxuICpcbiAqIEBwYXJhbSB7RnVuY3Rpb259IGZuXG4gKiBAcmV0dXJuIHtSZXF1ZXN0fSBmb3IgY2hhaW5pbmdcbiAqIEBhcGkgcHVibGljXG4gKi9cblxuUmVxdWVzdC5wcm90b3R5cGUuX2VtaXRSZXNwb25zZSA9IGZ1bmN0aW9uKGJvZHksIGZpbGVzKSB7XG4gIGNvbnN0IHJlc3BvbnNlID0gbmV3IFJlc3BvbnNlKHRoaXMpO1xuICB0aGlzLnJlc3BvbnNlID0gcmVzcG9uc2U7XG4gIHJlc3BvbnNlLnJlZGlyZWN0cyA9IHRoaXMuX3JlZGlyZWN0TGlzdDtcbiAgaWYgKHVuZGVmaW5lZCAhPT0gYm9keSkge1xuICAgIHJlc3BvbnNlLmJvZHkgPSBib2R5O1xuICB9XG5cbiAgcmVzcG9uc2UuZmlsZXMgPSBmaWxlcztcbiAgaWYgKHRoaXMuX2VuZENhbGxlZCkge1xuICAgIHJlc3BvbnNlLnBpcGUgPSBmdW5jdGlvbigpIHtcbiAgICAgIHRocm93IG5ldyBFcnJvcihcbiAgICAgICAgXCJlbmQoKSBoYXMgYWxyZWFkeSBiZWVuIGNhbGxlZCwgc28gaXQncyB0b28gbGF0ZSB0byBzdGFydCBwaXBpbmdcIlxuICAgICAgKTtcbiAgICB9O1xuICB9XG5cbiAgdGhpcy5lbWl0KCdyZXNwb25zZScsIHJlc3BvbnNlKTtcbiAgcmV0dXJuIHJlc3BvbnNlO1xufTtcblxuUmVxdWVzdC5wcm90b3R5cGUuZW5kID0gZnVuY3Rpb24oZm4pIHtcbiAgdGhpcy5yZXF1ZXN0KCk7XG4gIGRlYnVnKCclcyAlcycsIHRoaXMubWV0aG9kLCB0aGlzLnVybCk7XG5cbiAgaWYgKHRoaXMuX2VuZENhbGxlZCkge1xuICAgIHRocm93IG5ldyBFcnJvcihcbiAgICAgICcuZW5kKCkgd2FzIGNhbGxlZCB0d2ljZS4gVGhpcyBpcyBub3Qgc3VwcG9ydGVkIGluIHN1cGVyYWdlbnQnXG4gICAgKTtcbiAgfVxuXG4gIHRoaXMuX2VuZENhbGxlZCA9IHRydWU7XG5cbiAgLy8gc3RvcmUgY2FsbGJhY2tcbiAgdGhpcy5fY2FsbGJhY2sgPSBmbiB8fCBub29wO1xuXG4gIHRoaXMuX2VuZCgpO1xufTtcblxuUmVxdWVzdC5wcm90b3R5cGUuX2VuZCA9IGZ1bmN0aW9uKCkge1xuICBpZiAodGhpcy5fYWJvcnRlZClcbiAgICByZXR1cm4gdGhpcy5jYWxsYmFjayhcbiAgICAgIG5ldyBFcnJvcignVGhlIHJlcXVlc3QgaGFzIGJlZW4gYWJvcnRlZCBldmVuIGJlZm9yZSAuZW5kKCkgd2FzIGNhbGxlZCcpXG4gICAgKTtcblxuICBsZXQgZGF0YSA9IHRoaXMuX2RhdGE7XG4gIGNvbnN0IHsgcmVxIH0gPSB0aGlzO1xuICBjb25zdCB7IG1ldGhvZCB9ID0gdGhpcztcblxuICB0aGlzLl9zZXRUaW1lb3V0cygpO1xuXG4gIC8vIGJvZHlcbiAgaWYgKG1ldGhvZCAhPT0gJ0hFQUQnICYmICFyZXEuX2hlYWRlclNlbnQpIHtcbiAgICAvLyBzZXJpYWxpemUgc3R1ZmZcbiAgICBpZiAodHlwZW9mIGRhdGEgIT09ICdzdHJpbmcnKSB7XG4gICAgICBsZXQgY29udGVudFR5cGUgPSByZXEuZ2V0SGVhZGVyKCdDb250ZW50LVR5cGUnKTtcbiAgICAgIC8vIFBhcnNlIG91dCBqdXN0IHRoZSBjb250ZW50IHR5cGUgZnJvbSB0aGUgaGVhZGVyIChpZ25vcmUgdGhlIGNoYXJzZXQpXG4gICAgICBpZiAoY29udGVudFR5cGUpIGNvbnRlbnRUeXBlID0gY29udGVudFR5cGUuc3BsaXQoJzsnKVswXTtcbiAgICAgIGxldCBzZXJpYWxpemUgPSB0aGlzLl9zZXJpYWxpemVyIHx8IGV4cG9ydHMuc2VyaWFsaXplW2NvbnRlbnRUeXBlXTtcbiAgICAgIGlmICghc2VyaWFsaXplICYmIGlzSlNPTihjb250ZW50VHlwZSkpIHtcbiAgICAgICAgc2VyaWFsaXplID0gZXhwb3J0cy5zZXJpYWxpemVbJ2FwcGxpY2F0aW9uL2pzb24nXTtcbiAgICAgIH1cblxuICAgICAgaWYgKHNlcmlhbGl6ZSkgZGF0YSA9IHNlcmlhbGl6ZShkYXRhKTtcbiAgICB9XG5cbiAgICAvLyBjb250ZW50LWxlbmd0aFxuICAgIGlmIChkYXRhICYmICFyZXEuZ2V0SGVhZGVyKCdDb250ZW50LUxlbmd0aCcpKSB7XG4gICAgICByZXEuc2V0SGVhZGVyKFxuICAgICAgICAnQ29udGVudC1MZW5ndGgnLFxuICAgICAgICBCdWZmZXIuaXNCdWZmZXIoZGF0YSkgPyBkYXRhLmxlbmd0aCA6IEJ1ZmZlci5ieXRlTGVuZ3RoKGRhdGEpXG4gICAgICApO1xuICAgIH1cbiAgfVxuXG4gIC8vIHJlc3BvbnNlXG4gIC8vIGVzbGludC1kaXNhYmxlLW5leHQtbGluZSBjb21wbGV4aXR5XG4gIHJlcS5vbmNlKCdyZXNwb25zZScsIHJlcyA9PiB7XG4gICAgZGVidWcoJyVzICVzIC0+ICVzJywgdGhpcy5tZXRob2QsIHRoaXMudXJsLCByZXMuc3RhdHVzQ29kZSk7XG5cbiAgICBpZiAodGhpcy5fcmVzcG9uc2VUaW1lb3V0VGltZXIpIHtcbiAgICAgIGNsZWFyVGltZW91dCh0aGlzLl9yZXNwb25zZVRpbWVvdXRUaW1lcik7XG4gICAgfVxuXG4gICAgaWYgKHRoaXMucGlwZWQpIHtcbiAgICAgIHJldHVybjtcbiAgICB9XG5cbiAgICBjb25zdCBtYXggPSB0aGlzLl9tYXhSZWRpcmVjdHM7XG4gICAgY29uc3QgbWltZSA9IHV0aWxzLnR5cGUocmVzLmhlYWRlcnNbJ2NvbnRlbnQtdHlwZSddIHx8ICcnKSB8fCAndGV4dC9wbGFpbic7XG4gICAgY29uc3QgdHlwZSA9IG1pbWUuc3BsaXQoJy8nKVswXTtcbiAgICBjb25zdCBtdWx0aXBhcnQgPSB0eXBlID09PSAnbXVsdGlwYXJ0JztcbiAgICBjb25zdCByZWRpcmVjdCA9IGlzUmVkaXJlY3QocmVzLnN0YXR1c0NvZGUpO1xuICAgIGNvbnN0IHJlc3BvbnNlVHlwZSA9IHRoaXMuX3Jlc3BvbnNlVHlwZTtcblxuICAgIHRoaXMucmVzID0gcmVzO1xuXG4gICAgLy8gcmVkaXJlY3RcbiAgICBpZiAocmVkaXJlY3QgJiYgdGhpcy5fcmVkaXJlY3RzKysgIT09IG1heCkge1xuICAgICAgcmV0dXJuIHRoaXMuX3JlZGlyZWN0KHJlcyk7XG4gICAgfVxuXG4gICAgaWYgKHRoaXMubWV0aG9kID09PSAnSEVBRCcpIHtcbiAgICAgIHRoaXMuZW1pdCgnZW5kJyk7XG4gICAgICB0aGlzLmNhbGxiYWNrKG51bGwsIHRoaXMuX2VtaXRSZXNwb25zZSgpKTtcbiAgICAgIHJldHVybjtcbiAgICB9XG5cbiAgICAvLyB6bGliIHN1cHBvcnRcbiAgICBpZiAodGhpcy5fc2hvdWxkVW56aXAocmVzKSkge1xuICAgICAgdW56aXAocmVxLCByZXMpO1xuICAgIH1cblxuICAgIGxldCBidWZmZXIgPSB0aGlzLl9idWZmZXI7XG4gICAgaWYgKGJ1ZmZlciA9PT0gdW5kZWZpbmVkICYmIG1pbWUgaW4gZXhwb3J0cy5idWZmZXIpIHtcbiAgICAgIGJ1ZmZlciA9IEJvb2xlYW4oZXhwb3J0cy5idWZmZXJbbWltZV0pO1xuICAgIH1cblxuICAgIGxldCBwYXJzZXIgPSB0aGlzLl9wYXJzZXI7XG4gICAgaWYgKHVuZGVmaW5lZCA9PT0gYnVmZmVyKSB7XG4gICAgICBpZiAocGFyc2VyKSB7XG4gICAgICAgIGNvbnNvbGUud2FybihcbiAgICAgICAgICBcIkEgY3VzdG9tIHN1cGVyYWdlbnQgcGFyc2VyIGhhcyBiZWVuIHNldCwgYnV0IGJ1ZmZlcmluZyBzdHJhdGVneSBmb3IgdGhlIHBhcnNlciBoYXNuJ3QgYmVlbiBjb25maWd1cmVkLiBDYWxsIGByZXEuYnVmZmVyKHRydWUgb3IgZmFsc2UpYCBvciBzZXQgYHN1cGVyYWdlbnQuYnVmZmVyW21pbWVdID0gdHJ1ZSBvciBmYWxzZWBcIlxuICAgICAgICApO1xuICAgICAgICBidWZmZXIgPSB0cnVlO1xuICAgICAgfVxuICAgIH1cblxuICAgIGlmICghcGFyc2VyKSB7XG4gICAgICBpZiAocmVzcG9uc2VUeXBlKSB7XG4gICAgICAgIHBhcnNlciA9IGV4cG9ydHMucGFyc2UuaW1hZ2U7IC8vIEl0J3MgYWN0dWFsbHkgYSBnZW5lcmljIEJ1ZmZlclxuICAgICAgICBidWZmZXIgPSB0cnVlO1xuICAgICAgfSBlbHNlIGlmIChtdWx0aXBhcnQpIHtcbiAgICAgICAgY29uc3QgZm9ybSA9IG5ldyBmb3JtaWRhYmxlLkluY29taW5nRm9ybSgpO1xuICAgICAgICBwYXJzZXIgPSBmb3JtLnBhcnNlLmJpbmQoZm9ybSk7XG4gICAgICAgIGJ1ZmZlciA9IHRydWU7XG4gICAgICB9IGVsc2UgaWYgKGlzSW1hZ2VPclZpZGVvKG1pbWUpKSB7XG4gICAgICAgIHBhcnNlciA9IGV4cG9ydHMucGFyc2UuaW1hZ2U7XG4gICAgICAgIGJ1ZmZlciA9IHRydWU7IC8vIEZvciBiYWNrd2FyZHMtY29tcGF0aWJpbGl0eSBidWZmZXJpbmcgZGVmYXVsdCBpcyBhZC1ob2MgTUlNRS1kZXBlbmRlbnRcbiAgICAgIH0gZWxzZSBpZiAoZXhwb3J0cy5wYXJzZVttaW1lXSkge1xuICAgICAgICBwYXJzZXIgPSBleHBvcnRzLnBhcnNlW21pbWVdO1xuICAgICAgfSBlbHNlIGlmICh0eXBlID09PSAndGV4dCcpIHtcbiAgICAgICAgcGFyc2VyID0gZXhwb3J0cy5wYXJzZS50ZXh0O1xuICAgICAgICBidWZmZXIgPSBidWZmZXIgIT09IGZhbHNlO1xuXG4gICAgICAgIC8vIGV2ZXJ5b25lIHdhbnRzIHRoZWlyIG93biB3aGl0ZS1sYWJlbGVkIGpzb25cbiAgICAgIH0gZWxzZSBpZiAoaXNKU09OKG1pbWUpKSB7XG4gICAgICAgIHBhcnNlciA9IGV4cG9ydHMucGFyc2VbJ2FwcGxpY2F0aW9uL2pzb24nXTtcbiAgICAgICAgYnVmZmVyID0gYnVmZmVyICE9PSBmYWxzZTtcbiAgICAgIH0gZWxzZSBpZiAoYnVmZmVyKSB7XG4gICAgICAgIHBhcnNlciA9IGV4cG9ydHMucGFyc2UudGV4dDtcbiAgICAgIH0gZWxzZSBpZiAodW5kZWZpbmVkID09PSBidWZmZXIpIHtcbiAgICAgICAgcGFyc2VyID0gZXhwb3J0cy5wYXJzZS5pbWFnZTsgLy8gSXQncyBhY3R1YWxseSBhIGdlbmVyaWMgQnVmZmVyXG4gICAgICAgIGJ1ZmZlciA9IHRydWU7XG4gICAgICB9XG4gICAgfVxuXG4gICAgLy8gYnkgZGVmYXVsdCBvbmx5IGJ1ZmZlciB0ZXh0LyosIGpzb24gYW5kIG1lc3NlZCB1cCB0aGluZyBmcm9tIGhlbGxcbiAgICBpZiAoKHVuZGVmaW5lZCA9PT0gYnVmZmVyICYmIGlzVGV4dChtaW1lKSkgfHwgaXNKU09OKG1pbWUpKSB7XG4gICAgICBidWZmZXIgPSB0cnVlO1xuICAgIH1cblxuICAgIHRoaXMuX3Jlc0J1ZmZlcmVkID0gYnVmZmVyO1xuICAgIGxldCBwYXJzZXJIYW5kbGVzRW5kID0gZmFsc2U7XG4gICAgaWYgKGJ1ZmZlcikge1xuICAgICAgLy8gUHJvdGVjdGlvbmEgYWdhaW5zdCB6aXAgYm9tYnMgYW5kIG90aGVyIG51aXNhbmNlXG4gICAgICBsZXQgcmVzcG9uc2VCeXRlc0xlZnQgPSB0aGlzLl9tYXhSZXNwb25zZVNpemUgfHwgMjAwMDAwMDAwO1xuICAgICAgcmVzLm9uKCdkYXRhJywgYnVmID0+IHtcbiAgICAgICAgcmVzcG9uc2VCeXRlc0xlZnQgLT0gYnVmLmJ5dGVMZW5ndGggfHwgYnVmLmxlbmd0aDtcbiAgICAgICAgaWYgKHJlc3BvbnNlQnl0ZXNMZWZ0IDwgMCkge1xuICAgICAgICAgIC8vIFRoaXMgd2lsbCBwcm9wYWdhdGUgdGhyb3VnaCBlcnJvciBldmVudFxuICAgICAgICAgIGNvbnN0IGVyciA9IG5ldyBFcnJvcignTWF4aW11bSByZXNwb25zZSBzaXplIHJlYWNoZWQnKTtcbiAgICAgICAgICBlcnIuY29kZSA9ICdFVE9PTEFSR0UnO1xuICAgICAgICAgIC8vIFBhcnNlcnMgYXJlbid0IHJlcXVpcmVkIHRvIG9ic2VydmUgZXJyb3IgZXZlbnQsXG4gICAgICAgICAgLy8gc28gd291bGQgaW5jb3JyZWN0bHkgcmVwb3J0IHN1Y2Nlc3NcbiAgICAgICAgICBwYXJzZXJIYW5kbGVzRW5kID0gZmFsc2U7XG4gICAgICAgICAgLy8gV2lsbCBlbWl0IGVycm9yIGV2ZW50XG4gICAgICAgICAgcmVzLmRlc3Ryb3koZXJyKTtcbiAgICAgICAgfVxuICAgICAgfSk7XG4gICAgfVxuXG4gICAgaWYgKHBhcnNlcikge1xuICAgICAgdHJ5IHtcbiAgICAgICAgLy8gVW5idWZmZXJlZCBwYXJzZXJzIGFyZSBzdXBwb3NlZCB0byBlbWl0IHJlc3BvbnNlIGVhcmx5LFxuICAgICAgICAvLyB3aGljaCBpcyB3ZWlyZCBCVFcsIGJlY2F1c2UgcmVzcG9uc2UuYm9keSB3b24ndCBiZSB0aGVyZS5cbiAgICAgICAgcGFyc2VySGFuZGxlc0VuZCA9IGJ1ZmZlcjtcblxuICAgICAgICBwYXJzZXIocmVzLCAoZXJyLCBvYmosIGZpbGVzKSA9PiB7XG4gICAgICAgICAgaWYgKHRoaXMudGltZWRvdXQpIHtcbiAgICAgICAgICAgIC8vIFRpbWVvdXQgaGFzIGFscmVhZHkgaGFuZGxlZCBhbGwgY2FsbGJhY2tzXG4gICAgICAgICAgICByZXR1cm47XG4gICAgICAgICAgfVxuXG4gICAgICAgICAgLy8gSW50ZW50aW9uYWwgKG5vbi10aW1lb3V0KSBhYm9ydCBpcyBzdXBwb3NlZCB0byBwcmVzZXJ2ZSBwYXJ0aWFsIHJlc3BvbnNlLFxuICAgICAgICAgIC8vIGV2ZW4gaWYgaXQgZG9lc24ndCBwYXJzZS5cbiAgICAgICAgICBpZiAoZXJyICYmICF0aGlzLl9hYm9ydGVkKSB7XG4gICAgICAgICAgICByZXR1cm4gdGhpcy5jYWxsYmFjayhlcnIpO1xuICAgICAgICAgIH1cblxuICAgICAgICAgIGlmIChwYXJzZXJIYW5kbGVzRW5kKSB7XG4gICAgICAgICAgICB0aGlzLmVtaXQoJ2VuZCcpO1xuICAgICAgICAgICAgdGhpcy5jYWxsYmFjayhudWxsLCB0aGlzLl9lbWl0UmVzcG9uc2Uob2JqLCBmaWxlcykpO1xuICAgICAgICAgIH1cbiAgICAgICAgfSk7XG4gICAgICB9IGNhdGNoIChlcnIpIHtcbiAgICAgICAgdGhpcy5jYWxsYmFjayhlcnIpO1xuICAgICAgICByZXR1cm47XG4gICAgICB9XG4gICAgfVxuXG4gICAgdGhpcy5yZXMgPSByZXM7XG5cbiAgICAvLyB1bmJ1ZmZlcmVkXG4gICAgaWYgKCFidWZmZXIpIHtcbiAgICAgIGRlYnVnKCd1bmJ1ZmZlcmVkICVzICVzJywgdGhpcy5tZXRob2QsIHRoaXMudXJsKTtcbiAgICAgIHRoaXMuY2FsbGJhY2sobnVsbCwgdGhpcy5fZW1pdFJlc3BvbnNlKCkpO1xuICAgICAgaWYgKG11bHRpcGFydCkgcmV0dXJuOyAvLyBhbGxvdyBtdWx0aXBhcnQgdG8gaGFuZGxlIGVuZCBldmVudFxuICAgICAgcmVzLm9uY2UoJ2VuZCcsICgpID0+IHtcbiAgICAgICAgZGVidWcoJ2VuZCAlcyAlcycsIHRoaXMubWV0aG9kLCB0aGlzLnVybCk7XG4gICAgICAgIHRoaXMuZW1pdCgnZW5kJyk7XG4gICAgICB9KTtcbiAgICAgIHJldHVybjtcbiAgICB9XG5cbiAgICAvLyB0ZXJtaW5hdGluZyBldmVudHNcbiAgICByZXMub25jZSgnZXJyb3InLCBlcnIgPT4ge1xuICAgICAgcGFyc2VySGFuZGxlc0VuZCA9IGZhbHNlO1xuICAgICAgdGhpcy5jYWxsYmFjayhlcnIsIG51bGwpO1xuICAgIH0pO1xuICAgIGlmICghcGFyc2VySGFuZGxlc0VuZClcbiAgICAgIHJlcy5vbmNlKCdlbmQnLCAoKSA9PiB7XG4gICAgICAgIGRlYnVnKCdlbmQgJXMgJXMnLCB0aGlzLm1ldGhvZCwgdGhpcy51cmwpO1xuICAgICAgICAvLyBUT0RPOiB1bmxlc3MgYnVmZmVyaW5nIGVtaXQgZWFybGllciB0byBzdHJlYW1cbiAgICAgICAgdGhpcy5lbWl0KCdlbmQnKTtcbiAgICAgICAgdGhpcy5jYWxsYmFjayhudWxsLCB0aGlzLl9lbWl0UmVzcG9uc2UoKSk7XG4gICAgICB9KTtcbiAgfSk7XG5cbiAgdGhpcy5lbWl0KCdyZXF1ZXN0JywgdGhpcyk7XG5cbiAgY29uc3QgZ2V0UHJvZ3Jlc3NNb25pdG9yID0gKCkgPT4ge1xuICAgIGNvbnN0IGxlbmd0aENvbXB1dGFibGUgPSB0cnVlO1xuICAgIGNvbnN0IHRvdGFsID0gcmVxLmdldEhlYWRlcignQ29udGVudC1MZW5ndGgnKTtcbiAgICBsZXQgbG9hZGVkID0gMDtcblxuICAgIGNvbnN0IHByb2dyZXNzID0gbmV3IFN0cmVhbS5UcmFuc2Zvcm0oKTtcbiAgICBwcm9ncmVzcy5fdHJhbnNmb3JtID0gKGNodW5rLCBlbmNvZGluZywgY2IpID0+IHtcbiAgICAgIGxvYWRlZCArPSBjaHVuay5sZW5ndGg7XG4gICAgICB0aGlzLmVtaXQoJ3Byb2dyZXNzJywge1xuICAgICAgICBkaXJlY3Rpb246ICd1cGxvYWQnLFxuICAgICAgICBsZW5ndGhDb21wdXRhYmxlLFxuICAgICAgICBsb2FkZWQsXG4gICAgICAgIHRvdGFsXG4gICAgICB9KTtcbiAgICAgIGNiKG51bGwsIGNodW5rKTtcbiAgICB9O1xuXG4gICAgcmV0dXJuIHByb2dyZXNzO1xuICB9O1xuXG4gIGNvbnN0IGJ1ZmZlclRvQ2h1bmtzID0gYnVmZmVyID0+IHtcbiAgICBjb25zdCBjaHVua1NpemUgPSAxNiAqIDEwMjQ7IC8vIGRlZmF1bHQgaGlnaFdhdGVyTWFyayB2YWx1ZVxuICAgIGNvbnN0IGNodW5raW5nID0gbmV3IFN0cmVhbS5SZWFkYWJsZSgpO1xuICAgIGNvbnN0IHRvdGFsTGVuZ3RoID0gYnVmZmVyLmxlbmd0aDtcbiAgICBjb25zdCByZW1haW5kZXIgPSB0b3RhbExlbmd0aCAlIGNodW5rU2l6ZTtcbiAgICBjb25zdCBjdXRvZmYgPSB0b3RhbExlbmd0aCAtIHJlbWFpbmRlcjtcblxuICAgIGZvciAobGV0IGkgPSAwOyBpIDwgY3V0b2ZmOyBpICs9IGNodW5rU2l6ZSkge1xuICAgICAgY29uc3QgY2h1bmsgPSBidWZmZXIuc2xpY2UoaSwgaSArIGNodW5rU2l6ZSk7XG4gICAgICBjaHVua2luZy5wdXNoKGNodW5rKTtcbiAgICB9XG5cbiAgICBpZiAocmVtYWluZGVyID4gMCkge1xuICAgICAgY29uc3QgcmVtYWluZGVyQnVmZmVyID0gYnVmZmVyLnNsaWNlKC1yZW1haW5kZXIpO1xuICAgICAgY2h1bmtpbmcucHVzaChyZW1haW5kZXJCdWZmZXIpO1xuICAgIH1cblxuICAgIGNodW5raW5nLnB1c2gobnVsbCk7IC8vIG5vIG1vcmUgZGF0YVxuXG4gICAgcmV0dXJuIGNodW5raW5nO1xuICB9O1xuXG4gIC8vIGlmIGEgRm9ybURhdGEgaW5zdGFuY2UgZ290IGNyZWF0ZWQsIHRoZW4gd2Ugc2VuZCB0aGF0IGFzIHRoZSByZXF1ZXN0IGJvZHlcbiAgY29uc3QgZm9ybURhdGEgPSB0aGlzLl9mb3JtRGF0YTtcbiAgaWYgKGZvcm1EYXRhKSB7XG4gICAgLy8gc2V0IGhlYWRlcnNcbiAgICBjb25zdCBoZWFkZXJzID0gZm9ybURhdGEuZ2V0SGVhZGVycygpO1xuICAgIGZvciAoY29uc3QgaSBpbiBoZWFkZXJzKSB7XG4gICAgICBpZiAoT2JqZWN0LnByb3RvdHlwZS5oYXNPd25Qcm9wZXJ0eS5jYWxsKGhlYWRlcnMsIGkpKSB7XG4gICAgICAgIGRlYnVnKCdzZXR0aW5nIEZvcm1EYXRhIGhlYWRlcjogXCIlczogJXNcIicsIGksIGhlYWRlcnNbaV0pO1xuICAgICAgICByZXEuc2V0SGVhZGVyKGksIGhlYWRlcnNbaV0pO1xuICAgICAgfVxuICAgIH1cblxuICAgIC8vIGF0dGVtcHQgdG8gZ2V0IFwiQ29udGVudC1MZW5ndGhcIiBoZWFkZXJcbiAgICAvLyBlc2xpbnQtZGlzYWJsZS1uZXh0LWxpbmUgaGFuZGxlLWNhbGxiYWNrLWVyclxuICAgIGZvcm1EYXRhLmdldExlbmd0aCgoZXJyLCBsZW5ndGgpID0+IHtcbiAgICAgIC8vIFRPRE86IEFkZCBjaHVua2VkIGVuY29kaW5nIHdoZW4gbm8gbGVuZ3RoIChpZiBlcnIpXG5cbiAgICAgIGRlYnVnKCdnb3QgRm9ybURhdGEgQ29udGVudC1MZW5ndGg6ICVzJywgbGVuZ3RoKTtcbiAgICAgIGlmICh0eXBlb2YgbGVuZ3RoID09PSAnbnVtYmVyJykge1xuICAgICAgICByZXEuc2V0SGVhZGVyKCdDb250ZW50LUxlbmd0aCcsIGxlbmd0aCk7XG4gICAgICB9XG5cbiAgICAgIGZvcm1EYXRhLnBpcGUoZ2V0UHJvZ3Jlc3NNb25pdG9yKCkpLnBpcGUocmVxKTtcbiAgICB9KTtcbiAgfSBlbHNlIGlmIChCdWZmZXIuaXNCdWZmZXIoZGF0YSkpIHtcbiAgICBidWZmZXJUb0NodW5rcyhkYXRhKVxuICAgICAgLnBpcGUoZ2V0UHJvZ3Jlc3NNb25pdG9yKCkpXG4gICAgICAucGlwZShyZXEpO1xuICB9IGVsc2Uge1xuICAgIHJlcS5lbmQoZGF0YSk7XG4gIH1cbn07XG5cbi8vIENoZWNrIHdoZXRoZXIgcmVzcG9uc2UgaGFzIGEgbm9uLTAtc2l6ZWQgZ3ppcC1lbmNvZGVkIGJvZHlcblJlcXVlc3QucHJvdG90eXBlLl9zaG91bGRVbnppcCA9IHJlcyA9PiB7XG4gIGlmIChyZXMuc3RhdHVzQ29kZSA9PT0gMjA0IHx8IHJlcy5zdGF0dXNDb2RlID09PSAzMDQpIHtcbiAgICAvLyBUaGVzZSBhcmVuJ3Qgc3VwcG9zZWQgdG8gaGF2ZSBhbnkgYm9keVxuICAgIHJldHVybiBmYWxzZTtcbiAgfVxuXG4gIC8vIGhlYWRlciBjb250ZW50IGlzIGEgc3RyaW5nLCBhbmQgZGlzdGluY3Rpb24gYmV0d2VlbiAwIGFuZCBubyBpbmZvcm1hdGlvbiBpcyBjcnVjaWFsXG4gIGlmIChyZXMuaGVhZGVyc1snY29udGVudC1sZW5ndGgnXSA9PT0gJzAnKSB7XG4gICAgLy8gV2Uga25vdyB0aGF0IHRoZSBib2R5IGlzIGVtcHR5ICh1bmZvcnR1bmF0ZWx5LCB0aGlzIGNoZWNrIGRvZXMgbm90IGNvdmVyIGNodW5rZWQgZW5jb2RpbmcpXG4gICAgcmV0dXJuIGZhbHNlO1xuICB9XG5cbiAgLy8gY29uc29sZS5sb2cocmVzKTtcbiAgcmV0dXJuIC9eXFxzKig/OmRlZmxhdGV8Z3ppcClcXHMqJC8udGVzdChyZXMuaGVhZGVyc1snY29udGVudC1lbmNvZGluZyddKTtcbn07XG5cbi8qKlxuICogT3ZlcnJpZGVzIEROUyBmb3Igc2VsZWN0ZWQgaG9zdG5hbWVzLiBUYWtlcyBvYmplY3QgbWFwcGluZyBob3N0bmFtZXMgdG8gSVAgYWRkcmVzc2VzLlxuICpcbiAqIFdoZW4gbWFraW5nIGEgcmVxdWVzdCB0byBhIFVSTCB3aXRoIGEgaG9zdG5hbWUgZXhhY3RseSBtYXRjaGluZyBhIGtleSBpbiB0aGUgb2JqZWN0LFxuICogdXNlIHRoZSBnaXZlbiBJUCBhZGRyZXNzIHRvIGNvbm5lY3QsIGluc3RlYWQgb2YgdXNpbmcgRE5TIHRvIHJlc29sdmUgdGhlIGhvc3RuYW1lLlxuICpcbiAqIEEgc3BlY2lhbCBob3N0IGAqYCBtYXRjaGVzIGV2ZXJ5IGhvc3RuYW1lIChrZWVwIHJlZGlyZWN0cyBpbiBtaW5kISlcbiAqXG4gKiAgICAgIHJlcXVlc3QuY29ubmVjdCh7XG4gKiAgICAgICAgJ3Rlc3QuZXhhbXBsZS5jb20nOiAnMTI3LjAuMC4xJyxcbiAqICAgICAgICAnaXB2Ni5leGFtcGxlLmNvbSc6ICc6OjEnLFxuICogICAgICB9KVxuICovXG5SZXF1ZXN0LnByb3RvdHlwZS5jb25uZWN0ID0gZnVuY3Rpb24oY29ubmVjdE92ZXJyaWRlKSB7XG4gIGlmICh0eXBlb2YgY29ubmVjdE92ZXJyaWRlID09PSAnc3RyaW5nJykge1xuICAgIHRoaXMuX2Nvbm5lY3RPdmVycmlkZSA9IHsgJyonOiBjb25uZWN0T3ZlcnJpZGUgfTtcbiAgfSBlbHNlIGlmICh0eXBlb2YgY29ubmVjdE92ZXJyaWRlID09PSAnb2JqZWN0Jykge1xuICAgIHRoaXMuX2Nvbm5lY3RPdmVycmlkZSA9IGNvbm5lY3RPdmVycmlkZTtcbiAgfSBlbHNlIHtcbiAgICB0aGlzLl9jb25uZWN0T3ZlcnJpZGUgPSB1bmRlZmluZWQ7XG4gIH1cblxuICByZXR1cm4gdGhpcztcbn07XG5cblJlcXVlc3QucHJvdG90eXBlLnRydXN0TG9jYWxob3N0ID0gZnVuY3Rpb24odG9nZ2xlKSB7XG4gIHRoaXMuX3RydXN0TG9jYWxob3N0ID0gdG9nZ2xlID09PSB1bmRlZmluZWQgPyB0cnVlIDogdG9nZ2xlO1xuICByZXR1cm4gdGhpcztcbn07XG5cbi8vIGdlbmVyYXRlIEhUVFAgdmVyYiBtZXRob2RzXG5pZiAoIW1ldGhvZHMuaW5jbHVkZXMoJ2RlbCcpKSB7XG4gIC8vIGNyZWF0ZSBhIGNvcHkgc28gd2UgZG9uJ3QgY2F1c2UgY29uZmxpY3RzIHdpdGhcbiAgLy8gb3RoZXIgcGFja2FnZXMgdXNpbmcgdGhlIG1ldGhvZHMgcGFja2FnZSBhbmRcbiAgLy8gbnBtIDMueFxuICBtZXRob2RzID0gbWV0aG9kcy5zbGljZSgwKTtcbiAgbWV0aG9kcy5wdXNoKCdkZWwnKTtcbn1cblxubWV0aG9kcy5mb3JFYWNoKG1ldGhvZCA9PiB7XG4gIGNvbnN0IG5hbWUgPSBtZXRob2Q7XG4gIG1ldGhvZCA9IG1ldGhvZCA9PT0gJ2RlbCcgPyAnZGVsZXRlJyA6IG1ldGhvZDtcblxuICBtZXRob2QgPSBtZXRob2QudG9VcHBlckNhc2UoKTtcbiAgcmVxdWVzdFtuYW1lXSA9ICh1cmwsIGRhdGEsIGZuKSA9PiB7XG4gICAgY29uc3QgcmVxID0gcmVxdWVzdChtZXRob2QsIHVybCk7XG4gICAgaWYgKHR5cGVvZiBkYXRhID09PSAnZnVuY3Rpb24nKSB7XG4gICAgICBmbiA9IGRhdGE7XG4gICAgICBkYXRhID0gbnVsbDtcbiAgICB9XG5cbiAgICBpZiAoZGF0YSkge1xuICAgICAgaWYgKG1ldGhvZCA9PT0gJ0dFVCcgfHwgbWV0aG9kID09PSAnSEVBRCcpIHtcbiAgICAgICAgcmVxLnF1ZXJ5KGRhdGEpO1xuICAgICAgfSBlbHNlIHtcbiAgICAgICAgcmVxLnNlbmQoZGF0YSk7XG4gICAgICB9XG4gICAgfVxuXG4gICAgaWYgKGZuKSByZXEuZW5kKGZuKTtcbiAgICByZXR1cm4gcmVxO1xuICB9O1xufSk7XG5cbi8qKlxuICogQ2hlY2sgaWYgYG1pbWVgIGlzIHRleHQgYW5kIHNob3VsZCBiZSBidWZmZXJlZC5cbiAqXG4gKiBAcGFyYW0ge1N0cmluZ30gbWltZVxuICogQHJldHVybiB7Qm9vbGVhbn1cbiAqIEBhcGkgcHVibGljXG4gKi9cblxuZnVuY3Rpb24gaXNUZXh0KG1pbWUpIHtcbiAgY29uc3QgcGFydHMgPSBtaW1lLnNwbGl0KCcvJyk7XG4gIGNvbnN0IHR5cGUgPSBwYXJ0c1swXTtcbiAgY29uc3Qgc3VidHlwZSA9IHBhcnRzWzFdO1xuXG4gIHJldHVybiB0eXBlID09PSAndGV4dCcgfHwgc3VidHlwZSA9PT0gJ3gtd3d3LWZvcm0tdXJsZW5jb2RlZCc7XG59XG5cbmZ1bmN0aW9uIGlzSW1hZ2VPclZpZGVvKG1pbWUpIHtcbiAgY29uc3QgdHlwZSA9IG1pbWUuc3BsaXQoJy8nKVswXTtcblxuICByZXR1cm4gdHlwZSA9PT0gJ2ltYWdlJyB8fCB0eXBlID09PSAndmlkZW8nO1xufVxuXG4vKipcbiAqIENoZWNrIGlmIGBtaW1lYCBpcyBqc29uIG9yIGhhcyAranNvbiBzdHJ1Y3R1cmVkIHN5bnRheCBzdWZmaXguXG4gKlxuICogQHBhcmFtIHtTdHJpbmd9IG1pbWVcbiAqIEByZXR1cm4ge0Jvb2xlYW59XG4gKiBAYXBpIHByaXZhdGVcbiAqL1xuXG5mdW5jdGlvbiBpc0pTT04obWltZSkge1xuICAvLyBzaG91bGQgbWF0Y2ggL2pzb24gb3IgK2pzb25cbiAgLy8gYnV0IG5vdCAvanNvbi1zZXFcbiAgcmV0dXJuIC9bLytdanNvbigkfFteLVxcd10pLy50ZXN0KG1pbWUpO1xufVxuXG4vKipcbiAqIENoZWNrIGlmIHdlIHNob3VsZCBmb2xsb3cgdGhlIHJlZGlyZWN0IGBjb2RlYC5cbiAqXG4gKiBAcGFyYW0ge051bWJlcn0gY29kZVxuICogQHJldHVybiB7Qm9vbGVhbn1cbiAqIEBhcGkgcHJpdmF0ZVxuICovXG5cbmZ1bmN0aW9uIGlzUmVkaXJlY3QoY29kZSkge1xuICByZXR1cm4gWzMwMSwgMzAyLCAzMDMsIDMwNSwgMzA3LCAzMDhdLmluY2x1ZGVzKGNvZGUpO1xufVxuIl19
}, function(modId) {var map = {"../utils":1603008214467,"../request-base":1603008214468,"./unzip":1603008214470,"./response":1603008214471,"./http2wrapper":1603008214473,"./agent":1603008214474,"./parsers":1603008214476}; return __REQUIRE__(map[modId], modId); })
__DEFINE__(1603008214467, function(require, module, exports) {


/**
 * Return the mime type for the given `str`.
 *
 * @param {String} str
 * @return {String}
 * @api private
 */
exports.type = function (str) {
  return str.split(/ *; */).shift();
};
/**
 * Return header field parameters.
 *
 * @param {String} str
 * @return {Object}
 * @api private
 */


exports.params = function (str) {
  return str.split(/ *; */).reduce(function (obj, str) {
    var parts = str.split(/ *= */);
    var key = parts.shift();
    var val = parts.shift();
    if (key && val) obj[key] = val;
    return obj;
  }, {});
};
/**
 * Parse Link header fields.
 *
 * @param {String} str
 * @return {Object}
 * @api private
 */


exports.parseLinks = function (str) {
  return str.split(/ *, */).reduce(function (obj, str) {
    var parts = str.split(/ *; */);
    var url = parts[0].slice(1, -1);
    var rel = parts[1].split(/ *= */)[1].slice(1, -1);
    obj[rel] = url;
    return obj;
  }, {});
};
/**
 * Strip content related fields from `header`.
 *
 * @param {Object} header
 * @return {Object} header
 * @api private
 */


exports.cleanHeader = function (header, changesOrigin) {
  delete header['content-type'];
  delete header['content-length'];
  delete header['transfer-encoding'];
  delete header.host; // secuirty

  if (changesOrigin) {
    delete header.authorization;
    delete header.cookie;
  }

  return header;
};
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbIi4uL3NyYy91dGlscy5qcyJdLCJuYW1lcyI6WyJleHBvcnRzIiwidHlwZSIsInN0ciIsInNwbGl0Iiwic2hpZnQiLCJwYXJhbXMiLCJyZWR1Y2UiLCJvYmoiLCJwYXJ0cyIsImtleSIsInZhbCIsInBhcnNlTGlua3MiLCJ1cmwiLCJzbGljZSIsInJlbCIsImNsZWFuSGVhZGVyIiwiaGVhZGVyIiwiY2hhbmdlc09yaWdpbiIsImhvc3QiLCJhdXRob3JpemF0aW9uIiwiY29va2llIl0sIm1hcHBpbmdzIjoiOztBQUFBOzs7Ozs7O0FBUUFBLE9BQU8sQ0FBQ0MsSUFBUixHQUFlLFVBQUFDLEdBQUc7QUFBQSxTQUFJQSxHQUFHLENBQUNDLEtBQUosQ0FBVSxPQUFWLEVBQW1CQyxLQUFuQixFQUFKO0FBQUEsQ0FBbEI7QUFFQTs7Ozs7Ozs7O0FBUUFKLE9BQU8sQ0FBQ0ssTUFBUixHQUFpQixVQUFBSCxHQUFHO0FBQUEsU0FDbEJBLEdBQUcsQ0FBQ0MsS0FBSixDQUFVLE9BQVYsRUFBbUJHLE1BQW5CLENBQTBCLFVBQUNDLEdBQUQsRUFBTUwsR0FBTixFQUFjO0FBQ3RDLFFBQU1NLEtBQUssR0FBR04sR0FBRyxDQUFDQyxLQUFKLENBQVUsT0FBVixDQUFkO0FBQ0EsUUFBTU0sR0FBRyxHQUFHRCxLQUFLLENBQUNKLEtBQU4sRUFBWjtBQUNBLFFBQU1NLEdBQUcsR0FBR0YsS0FBSyxDQUFDSixLQUFOLEVBQVo7QUFFQSxRQUFJSyxHQUFHLElBQUlDLEdBQVgsRUFBZ0JILEdBQUcsQ0FBQ0UsR0FBRCxDQUFILEdBQVdDLEdBQVg7QUFDaEIsV0FBT0gsR0FBUDtBQUNELEdBUEQsRUFPRyxFQVBILENBRGtCO0FBQUEsQ0FBcEI7QUFVQTs7Ozs7Ozs7O0FBUUFQLE9BQU8sQ0FBQ1csVUFBUixHQUFxQixVQUFBVCxHQUFHO0FBQUEsU0FDdEJBLEdBQUcsQ0FBQ0MsS0FBSixDQUFVLE9BQVYsRUFBbUJHLE1BQW5CLENBQTBCLFVBQUNDLEdBQUQsRUFBTUwsR0FBTixFQUFjO0FBQ3RDLFFBQU1NLEtBQUssR0FBR04sR0FBRyxDQUFDQyxLQUFKLENBQVUsT0FBVixDQUFkO0FBQ0EsUUFBTVMsR0FBRyxHQUFHSixLQUFLLENBQUMsQ0FBRCxDQUFMLENBQVNLLEtBQVQsQ0FBZSxDQUFmLEVBQWtCLENBQUMsQ0FBbkIsQ0FBWjtBQUNBLFFBQU1DLEdBQUcsR0FBR04sS0FBSyxDQUFDLENBQUQsQ0FBTCxDQUFTTCxLQUFULENBQWUsT0FBZixFQUF3QixDQUF4QixFQUEyQlUsS0FBM0IsQ0FBaUMsQ0FBakMsRUFBb0MsQ0FBQyxDQUFyQyxDQUFaO0FBQ0FOLElBQUFBLEdBQUcsQ0FBQ08sR0FBRCxDQUFILEdBQVdGLEdBQVg7QUFDQSxXQUFPTCxHQUFQO0FBQ0QsR0FORCxFQU1HLEVBTkgsQ0FEc0I7QUFBQSxDQUF4QjtBQVNBOzs7Ozs7Ozs7QUFRQVAsT0FBTyxDQUFDZSxXQUFSLEdBQXNCLFVBQUNDLE1BQUQsRUFBU0MsYUFBVCxFQUEyQjtBQUMvQyxTQUFPRCxNQUFNLENBQUMsY0FBRCxDQUFiO0FBQ0EsU0FBT0EsTUFBTSxDQUFDLGdCQUFELENBQWI7QUFDQSxTQUFPQSxNQUFNLENBQUMsbUJBQUQsQ0FBYjtBQUNBLFNBQU9BLE1BQU0sQ0FBQ0UsSUFBZCxDQUorQyxDQUsvQzs7QUFDQSxNQUFJRCxhQUFKLEVBQW1CO0FBQ2pCLFdBQU9ELE1BQU0sQ0FBQ0csYUFBZDtBQUNBLFdBQU9ILE1BQU0sQ0FBQ0ksTUFBZDtBQUNEOztBQUVELFNBQU9KLE1BQVA7QUFDRCxDQVpEIiwic291cmNlc0NvbnRlbnQiOlsiLyoqXG4gKiBSZXR1cm4gdGhlIG1pbWUgdHlwZSBmb3IgdGhlIGdpdmVuIGBzdHJgLlxuICpcbiAqIEBwYXJhbSB7U3RyaW5nfSBzdHJcbiAqIEByZXR1cm4ge1N0cmluZ31cbiAqIEBhcGkgcHJpdmF0ZVxuICovXG5cbmV4cG9ydHMudHlwZSA9IHN0ciA9PiBzdHIuc3BsaXQoLyAqOyAqLykuc2hpZnQoKTtcblxuLyoqXG4gKiBSZXR1cm4gaGVhZGVyIGZpZWxkIHBhcmFtZXRlcnMuXG4gKlxuICogQHBhcmFtIHtTdHJpbmd9IHN0clxuICogQHJldHVybiB7T2JqZWN0fVxuICogQGFwaSBwcml2YXRlXG4gKi9cblxuZXhwb3J0cy5wYXJhbXMgPSBzdHIgPT5cbiAgc3RyLnNwbGl0KC8gKjsgKi8pLnJlZHVjZSgob2JqLCBzdHIpID0+IHtcbiAgICBjb25zdCBwYXJ0cyA9IHN0ci5zcGxpdCgvICo9ICovKTtcbiAgICBjb25zdCBrZXkgPSBwYXJ0cy5zaGlmdCgpO1xuICAgIGNvbnN0IHZhbCA9IHBhcnRzLnNoaWZ0KCk7XG5cbiAgICBpZiAoa2V5ICYmIHZhbCkgb2JqW2tleV0gPSB2YWw7XG4gICAgcmV0dXJuIG9iajtcbiAgfSwge30pO1xuXG4vKipcbiAqIFBhcnNlIExpbmsgaGVhZGVyIGZpZWxkcy5cbiAqXG4gKiBAcGFyYW0ge1N0cmluZ30gc3RyXG4gKiBAcmV0dXJuIHtPYmplY3R9XG4gKiBAYXBpIHByaXZhdGVcbiAqL1xuXG5leHBvcnRzLnBhcnNlTGlua3MgPSBzdHIgPT5cbiAgc3RyLnNwbGl0KC8gKiwgKi8pLnJlZHVjZSgob2JqLCBzdHIpID0+IHtcbiAgICBjb25zdCBwYXJ0cyA9IHN0ci5zcGxpdCgvICo7ICovKTtcbiAgICBjb25zdCB1cmwgPSBwYXJ0c1swXS5zbGljZSgxLCAtMSk7XG4gICAgY29uc3QgcmVsID0gcGFydHNbMV0uc3BsaXQoLyAqPSAqLylbMV0uc2xpY2UoMSwgLTEpO1xuICAgIG9ialtyZWxdID0gdXJsO1xuICAgIHJldHVybiBvYmo7XG4gIH0sIHt9KTtcblxuLyoqXG4gKiBTdHJpcCBjb250ZW50IHJlbGF0ZWQgZmllbGRzIGZyb20gYGhlYWRlcmAuXG4gKlxuICogQHBhcmFtIHtPYmplY3R9IGhlYWRlclxuICogQHJldHVybiB7T2JqZWN0fSBoZWFkZXJcbiAqIEBhcGkgcHJpdmF0ZVxuICovXG5cbmV4cG9ydHMuY2xlYW5IZWFkZXIgPSAoaGVhZGVyLCBjaGFuZ2VzT3JpZ2luKSA9PiB7XG4gIGRlbGV0ZSBoZWFkZXJbJ2NvbnRlbnQtdHlwZSddO1xuICBkZWxldGUgaGVhZGVyWydjb250ZW50LWxlbmd0aCddO1xuICBkZWxldGUgaGVhZGVyWyd0cmFuc2Zlci1lbmNvZGluZyddO1xuICBkZWxldGUgaGVhZGVyLmhvc3Q7XG4gIC8vIHNlY3VpcnR5XG4gIGlmIChjaGFuZ2VzT3JpZ2luKSB7XG4gICAgZGVsZXRlIGhlYWRlci5hdXRob3JpemF0aW9uO1xuICAgIGRlbGV0ZSBoZWFkZXIuY29va2llO1xuICB9XG5cbiAgcmV0dXJuIGhlYWRlcjtcbn07XG4iXX0=
}, function(modId) { var map = {}; return __REQUIRE__(map[modId], modId); })
__DEFINE__(1603008214468, function(require, module, exports) {


function _typeof(obj) { "@babel/helpers - typeof"; if (typeof Symbol === "function" && typeof Symbol.iterator === "symbol") { _typeof = function _typeof(obj) { return typeof obj; }; } else { _typeof = function _typeof(obj) { return obj && typeof Symbol === "function" && obj.constructor === Symbol && obj !== Symbol.prototype ? "symbol" : typeof obj; }; } return _typeof(obj); }

/**
 * Module of mixed-in functions shared between node and client code
 */
var isObject = require('./is-object');
/**
 * Expose `RequestBase`.
 */


module.exports = RequestBase;
/**
 * Initialize a new `RequestBase`.
 *
 * @api public
 */

function RequestBase(obj) {
  if (obj) return mixin(obj);
}
/**
 * Mixin the prototype properties.
 *
 * @param {Object} obj
 * @return {Object}
 * @api private
 */


function mixin(obj) {
  for (var key in RequestBase.prototype) {
    if (Object.prototype.hasOwnProperty.call(RequestBase.prototype, key)) obj[key] = RequestBase.prototype[key];
  }

  return obj;
}
/**
 * Clear previous timeout.
 *
 * @return {Request} for chaining
 * @api public
 */


RequestBase.prototype.clearTimeout = function () {
  clearTimeout(this._timer);
  clearTimeout(this._responseTimeoutTimer);
  clearTimeout(this._uploadTimeoutTimer);
  delete this._timer;
  delete this._responseTimeoutTimer;
  delete this._uploadTimeoutTimer;
  return this;
};
/**
 * Override default response body parser
 *
 * This function will be called to convert incoming data into request.body
 *
 * @param {Function}
 * @api public
 */


RequestBase.prototype.parse = function (fn) {
  this._parser = fn;
  return this;
};
/**
 * Set format of binary response body.
 * In browser valid formats are 'blob' and 'arraybuffer',
 * which return Blob and ArrayBuffer, respectively.
 *
 * In Node all values result in Buffer.
 *
 * Examples:
 *
 *      req.get('/')
 *        .responseType('blob')
 *        .end(callback);
 *
 * @param {String} val
 * @return {Request} for chaining
 * @api public
 */


RequestBase.prototype.responseType = function (val) {
  this._responseType = val;
  return this;
};
/**
 * Override default request body serializer
 *
 * This function will be called to convert data set via .send or .attach into payload to send
 *
 * @param {Function}
 * @api public
 */


RequestBase.prototype.serialize = function (fn) {
  this._serializer = fn;
  return this;
};
/**
 * Set timeouts.
 *
 * - response timeout is time between sending request and receiving the first byte of the response. Includes DNS and connection time.
 * - deadline is the time from start of the request to receiving response body in full. If the deadline is too short large files may not load at all on slow connections.
 * - upload is the time  since last bit of data was sent or received. This timeout works only if deadline timeout is off
 *
 * Value of 0 or false means no timeout.
 *
 * @param {Number|Object} ms or {response, deadline}
 * @return {Request} for chaining
 * @api public
 */


RequestBase.prototype.timeout = function (options) {
  if (!options || _typeof(options) !== 'object') {
    this._timeout = options;
    this._responseTimeout = 0;
    this._uploadTimeout = 0;
    return this;
  }

  for (var option in options) {
    if (Object.prototype.hasOwnProperty.call(options, option)) {
      switch (option) {
        case 'deadline':
          this._timeout = options.deadline;
          break;

        case 'response':
          this._responseTimeout = options.response;
          break;

        case 'upload':
          this._uploadTimeout = options.upload;
          break;

        default:
          console.warn('Unknown timeout option', option);
      }
    }
  }

  return this;
};
/**
 * Set number of retry attempts on error.
 *
 * Failed requests will be retried 'count' times if timeout or err.code >= 500.
 *
 * @param {Number} count
 * @param {Function} [fn]
 * @return {Request} for chaining
 * @api public
 */


RequestBase.prototype.retry = function (count, fn) {
  // Default to 1 if no count passed or true
  if (arguments.length === 0 || count === true) count = 1;
  if (count <= 0) count = 0;
  this._maxRetries = count;
  this._retries = 0;
  this._retryCallback = fn;
  return this;
};

var ERROR_CODES = ['ECONNRESET', 'ETIMEDOUT', 'EADDRINFO', 'ESOCKETTIMEDOUT'];
/**
 * Determine if a request should be retried.
 * (Borrowed from segmentio/superagent-retry)
 *
 * @param {Error} err an error
 * @param {Response} [res] response
 * @returns {Boolean} if segment should be retried
 */

RequestBase.prototype._shouldRetry = function (err, res) {
  if (!this._maxRetries || this._retries++ >= this._maxRetries) {
    return false;
  }

  if (this._retryCallback) {
    try {
      var override = this._retryCallback(err, res);

      if (override === true) return true;
      if (override === false) return false; // undefined falls back to defaults
    } catch (err_) {
      console.error(err_);
    }
  }

  if (res && res.status && res.status >= 500 && res.status !== 501) return true;

  if (err) {
    if (err.code && ERROR_CODES.includes(err.code)) return true; // Superagent timeout

    if (err.timeout && err.code === 'ECONNABORTED') return true;
    if (err.crossDomain) return true;
  }

  return false;
};
/**
 * Retry request
 *
 * @return {Request} for chaining
 * @api private
 */


RequestBase.prototype._retry = function () {
  this.clearTimeout(); // node

  if (this.req) {
    this.req = null;
    this.req = this.request();
  }

  this._aborted = false;
  this.timedout = false;
  this.timedoutError = null;
  return this._end();
};
/**
 * Promise support
 *
 * @param {Function} resolve
 * @param {Function} [reject]
 * @return {Request}
 */


RequestBase.prototype.then = function (resolve, reject) {
  var _this = this;

  if (!this._fullfilledPromise) {
    var self = this;

    if (this._endCalled) {
      console.warn('Warning: superagent request was sent twice, because both .end() and .then() were called. Never call .end() if you use promises');
    }

    this._fullfilledPromise = new Promise(function (resolve, reject) {
      self.on('abort', function () {
        if (_this._maxRetries && _this._maxRetries > _this._retries) {
          return;
        }

        if (_this.timedout && _this.timedoutError) {
          reject(_this.timedoutError);
          return;
        }

        var err = new Error('Aborted');
        err.code = 'ABORTED';
        err.status = _this.status;
        err.method = _this.method;
        err.url = _this.url;
        reject(err);
      });
      self.end(function (err, res) {
        if (err) reject(err);else resolve(res);
      });
    });
  }

  return this._fullfilledPromise.then(resolve, reject);
};

RequestBase.prototype.catch = function (cb) {
  return this.then(undefined, cb);
};
/**
 * Allow for extension
 */


RequestBase.prototype.use = function (fn) {
  fn(this);
  return this;
};

RequestBase.prototype.ok = function (cb) {
  if (typeof cb !== 'function') throw new Error('Callback required');
  this._okCallback = cb;
  return this;
};

RequestBase.prototype._isResponseOK = function (res) {
  if (!res) {
    return false;
  }

  if (this._okCallback) {
    return this._okCallback(res);
  }

  return res.status >= 200 && res.status < 300;
};
/**
 * Get request header `field`.
 * Case-insensitive.
 *
 * @param {String} field
 * @return {String}
 * @api public
 */


RequestBase.prototype.get = function (field) {
  return this._header[field.toLowerCase()];
};
/**
 * Get case-insensitive header `field` value.
 * This is a deprecated internal API. Use `.get(field)` instead.
 *
 * (getHeader is no longer used internally by the superagent code base)
 *
 * @param {String} field
 * @return {String}
 * @api private
 * @deprecated
 */


RequestBase.prototype.getHeader = RequestBase.prototype.get;
/**
 * Set header `field` to `val`, or multiple fields with one object.
 * Case-insensitive.
 *
 * Examples:
 *
 *      req.get('/')
 *        .set('Accept', 'application/json')
 *        .set('X-API-Key', 'foobar')
 *        .end(callback);
 *
 *      req.get('/')
 *        .set({ Accept: 'application/json', 'X-API-Key': 'foobar' })
 *        .end(callback);
 *
 * @param {String|Object} field
 * @param {String} val
 * @return {Request} for chaining
 * @api public
 */

RequestBase.prototype.set = function (field, val) {
  if (isObject(field)) {
    for (var key in field) {
      if (Object.prototype.hasOwnProperty.call(field, key)) this.set(key, field[key]);
    }

    return this;
  }

  this._header[field.toLowerCase()] = val;
  this.header[field] = val;
  return this;
};
/**
 * Remove header `field`.
 * Case-insensitive.
 *
 * Example:
 *
 *      req.get('/')
 *        .unset('User-Agent')
 *        .end(callback);
 *
 * @param {String} field field name
 */


RequestBase.prototype.unset = function (field) {
  delete this._header[field.toLowerCase()];
  delete this.header[field];
  return this;
};
/**
 * Write the field `name` and `val`, or multiple fields with one object
 * for "multipart/form-data" request bodies.
 *
 * ``` js
 * request.post('/upload')
 *   .field('foo', 'bar')
 *   .end(callback);
 *
 * request.post('/upload')
 *   .field({ foo: 'bar', baz: 'qux' })
 *   .end(callback);
 * ```
 *
 * @param {String|Object} name name of field
 * @param {String|Blob|File|Buffer|fs.ReadStream} val value of field
 * @return {Request} for chaining
 * @api public
 */


RequestBase.prototype.field = function (name, val) {
  // name should be either a string or an object.
  if (name === null || undefined === name) {
    throw new Error('.field(name, val) name can not be empty');
  }

  if (this._data) {
    throw new Error(".field() can't be used if .send() is used. Please use only .send() or only .field() & .attach()");
  }

  if (isObject(name)) {
    for (var key in name) {
      if (Object.prototype.hasOwnProperty.call(name, key)) this.field(key, name[key]);
    }

    return this;
  }

  if (Array.isArray(val)) {
    for (var i in val) {
      if (Object.prototype.hasOwnProperty.call(val, i)) this.field(name, val[i]);
    }

    return this;
  } // val should be defined now


  if (val === null || undefined === val) {
    throw new Error('.field(name, val) val can not be empty');
  }

  if (typeof val === 'boolean') {
    val = String(val);
  }

  this._getFormData().append(name, val);

  return this;
};
/**
 * Abort the request, and clear potential timeout.
 *
 * @return {Request} request
 * @api public
 */


RequestBase.prototype.abort = function () {
  if (this._aborted) {
    return this;
  }

  this._aborted = true;
  if (this.xhr) this.xhr.abort(); // browser

  if (this.req) this.req.abort(); // node

  this.clearTimeout();
  this.emit('abort');
  return this;
};

RequestBase.prototype._auth = function (user, pass, options, base64Encoder) {
  switch (options.type) {
    case 'basic':
      this.set('Authorization', "Basic ".concat(base64Encoder("".concat(user, ":").concat(pass))));
      break;

    case 'auto':
      this.username = user;
      this.password = pass;
      break;

    case 'bearer':
      // usage would be .auth(accessToken, { type: 'bearer' })
      this.set('Authorization', "Bearer ".concat(user));
      break;

    default:
      break;
  }

  return this;
};
/**
 * Enable transmission of cookies with x-domain requests.
 *
 * Note that for this to work the origin must not be
 * using "Access-Control-Allow-Origin" with a wildcard,
 * and also must set "Access-Control-Allow-Credentials"
 * to "true".
 *
 * @api public
 */


RequestBase.prototype.withCredentials = function (on) {
  // This is browser-only functionality. Node side is no-op.
  if (on === undefined) on = true;
  this._withCredentials = on;
  return this;
};
/**
 * Set the max redirects to `n`. Does nothing in browser XHR implementation.
 *
 * @param {Number} n
 * @return {Request} for chaining
 * @api public
 */


RequestBase.prototype.redirects = function (n) {
  this._maxRedirects = n;
  return this;
};
/**
 * Maximum size of buffered response body, in bytes. Counts uncompressed size.
 * Default 200MB.
 *
 * @param {Number} n number of bytes
 * @return {Request} for chaining
 */


RequestBase.prototype.maxResponseSize = function (n) {
  if (typeof n !== 'number') {
    throw new TypeError('Invalid argument');
  }

  this._maxResponseSize = n;
  return this;
};
/**
 * Convert to a plain javascript object (not JSON string) of scalar properties.
 * Note as this method is designed to return a useful non-this value,
 * it cannot be chained.
 *
 * @return {Object} describing method, url, and data of this request
 * @api public
 */


RequestBase.prototype.toJSON = function () {
  return {
    method: this.method,
    url: this.url,
    data: this._data,
    headers: this._header
  };
};
/**
 * Send `data` as the request body, defaulting the `.type()` to "json" when
 * an object is given.
 *
 * Examples:
 *
 *       // manual json
 *       request.post('/user')
 *         .type('json')
 *         .send('{"name":"tj"}')
 *         .end(callback)
 *
 *       // auto json
 *       request.post('/user')
 *         .send({ name: 'tj' })
 *         .end(callback)
 *
 *       // manual x-www-form-urlencoded
 *       request.post('/user')
 *         .type('form')
 *         .send('name=tj')
 *         .end(callback)
 *
 *       // auto x-www-form-urlencoded
 *       request.post('/user')
 *         .type('form')
 *         .send({ name: 'tj' })
 *         .end(callback)
 *
 *       // defaults to x-www-form-urlencoded
 *      request.post('/user')
 *        .send('name=tobi')
 *        .send('species=ferret')
 *        .end(callback)
 *
 * @param {String|Object} data
 * @return {Request} for chaining
 * @api public
 */
// eslint-disable-next-line complexity


RequestBase.prototype.send = function (data) {
  var isObj = isObject(data);
  var type = this._header['content-type'];

  if (this._formData) {
    throw new Error(".send() can't be used if .attach() or .field() is used. Please use only .send() or only .field() & .attach()");
  }

  if (isObj && !this._data) {
    if (Array.isArray(data)) {
      this._data = [];
    } else if (!this._isHost(data)) {
      this._data = {};
    }
  } else if (data && this._data && this._isHost(this._data)) {
    throw new Error("Can't merge these send calls");
  } // merge


  if (isObj && isObject(this._data)) {
    for (var key in data) {
      if (Object.prototype.hasOwnProperty.call(data, key)) this._data[key] = data[key];
    }
  } else if (typeof data === 'string') {
    // default to x-www-form-urlencoded
    if (!type) this.type('form');
    type = this._header['content-type'];

    if (type === 'application/x-www-form-urlencoded') {
      this._data = this._data ? "".concat(this._data, "&").concat(data) : data;
    } else {
      this._data = (this._data || '') + data;
    }
  } else {
    this._data = data;
  }

  if (!isObj || this._isHost(data)) {
    return this;
  } // default to json


  if (!type) this.type('json');
  return this;
};
/**
 * Sort `querystring` by the sort function
 *
 *
 * Examples:
 *
 *       // default order
 *       request.get('/user')
 *         .query('name=Nick')
 *         .query('search=Manny')
 *         .sortQuery()
 *         .end(callback)
 *
 *       // customized sort function
 *       request.get('/user')
 *         .query('name=Nick')
 *         .query('search=Manny')
 *         .sortQuery(function(a, b){
 *           return a.length - b.length;
 *         })
 *         .end(callback)
 *
 *
 * @param {Function} sort
 * @return {Request} for chaining
 * @api public
 */


RequestBase.prototype.sortQuery = function (sort) {
  // _sort default to true but otherwise can be a function or boolean
  this._sort = typeof sort === 'undefined' ? true : sort;
  return this;
};
/**
 * Compose querystring to append to req.url
 *
 * @api private
 */


RequestBase.prototype._finalizeQueryString = function () {
  var query = this._query.join('&');

  if (query) {
    this.url += (this.url.includes('?') ? '&' : '?') + query;
  }

  this._query.length = 0; // Makes the call idempotent

  if (this._sort) {
    var index = this.url.indexOf('?');

    if (index >= 0) {
      var queryArr = this.url.slice(index + 1).split('&');

      if (typeof this._sort === 'function') {
        queryArr.sort(this._sort);
      } else {
        queryArr.sort();
      }

      this.url = this.url.slice(0, index) + '?' + queryArr.join('&');
    }
  }
}; // For backwards compat only


RequestBase.prototype._appendQueryString = function () {
  console.warn('Unsupported');
};
/**
 * Invoke callback with timeout error.
 *
 * @api private
 */


RequestBase.prototype._timeoutError = function (reason, timeout, errno) {
  if (this._aborted) {
    return;
  }

  var err = new Error("".concat(reason + timeout, "ms exceeded"));
  err.timeout = timeout;
  err.code = 'ECONNABORTED';
  err.errno = errno;
  this.timedout = true;
  this.timedoutError = err;
  this.abort();
  this.callback(err);
};

RequestBase.prototype._setTimeouts = function () {
  var self = this; // deadline

  if (this._timeout && !this._timer) {
    this._timer = setTimeout(function () {
      self._timeoutError('Timeout of ', self._timeout, 'ETIME');
    }, this._timeout);
  } // response timeout


  if (this._responseTimeout && !this._responseTimeoutTimer) {
    this._responseTimeoutTimer = setTimeout(function () {
      self._timeoutError('Response timeout of ', self._responseTimeout, 'ETIMEDOUT');
    }, this._responseTimeout);
  }
};
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbIi4uL3NyYy9yZXF1ZXN0LWJhc2UuanMiXSwibmFtZXMiOlsiaXNPYmplY3QiLCJyZXF1aXJlIiwibW9kdWxlIiwiZXhwb3J0cyIsIlJlcXVlc3RCYXNlIiwib2JqIiwibWl4aW4iLCJrZXkiLCJwcm90b3R5cGUiLCJPYmplY3QiLCJoYXNPd25Qcm9wZXJ0eSIsImNhbGwiLCJjbGVhclRpbWVvdXQiLCJfdGltZXIiLCJfcmVzcG9uc2VUaW1lb3V0VGltZXIiLCJfdXBsb2FkVGltZW91dFRpbWVyIiwicGFyc2UiLCJmbiIsIl9wYXJzZXIiLCJyZXNwb25zZVR5cGUiLCJ2YWwiLCJfcmVzcG9uc2VUeXBlIiwic2VyaWFsaXplIiwiX3NlcmlhbGl6ZXIiLCJ0aW1lb3V0Iiwib3B0aW9ucyIsIl90aW1lb3V0IiwiX3Jlc3BvbnNlVGltZW91dCIsIl91cGxvYWRUaW1lb3V0Iiwib3B0aW9uIiwiZGVhZGxpbmUiLCJyZXNwb25zZSIsInVwbG9hZCIsImNvbnNvbGUiLCJ3YXJuIiwicmV0cnkiLCJjb3VudCIsImFyZ3VtZW50cyIsImxlbmd0aCIsIl9tYXhSZXRyaWVzIiwiX3JldHJpZXMiLCJfcmV0cnlDYWxsYmFjayIsIkVSUk9SX0NPREVTIiwiX3Nob3VsZFJldHJ5IiwiZXJyIiwicmVzIiwib3ZlcnJpZGUiLCJlcnJfIiwiZXJyb3IiLCJzdGF0dXMiLCJjb2RlIiwiaW5jbHVkZXMiLCJjcm9zc0RvbWFpbiIsIl9yZXRyeSIsInJlcSIsInJlcXVlc3QiLCJfYWJvcnRlZCIsInRpbWVkb3V0IiwidGltZWRvdXRFcnJvciIsIl9lbmQiLCJ0aGVuIiwicmVzb2x2ZSIsInJlamVjdCIsIl9mdWxsZmlsbGVkUHJvbWlzZSIsInNlbGYiLCJfZW5kQ2FsbGVkIiwiUHJvbWlzZSIsIm9uIiwiRXJyb3IiLCJtZXRob2QiLCJ1cmwiLCJlbmQiLCJjYXRjaCIsImNiIiwidW5kZWZpbmVkIiwidXNlIiwib2siLCJfb2tDYWxsYmFjayIsIl9pc1Jlc3BvbnNlT0siLCJnZXQiLCJmaWVsZCIsIl9oZWFkZXIiLCJ0b0xvd2VyQ2FzZSIsImdldEhlYWRlciIsInNldCIsImhlYWRlciIsInVuc2V0IiwibmFtZSIsIl9kYXRhIiwiQXJyYXkiLCJpc0FycmF5IiwiaSIsIlN0cmluZyIsIl9nZXRGb3JtRGF0YSIsImFwcGVuZCIsImFib3J0IiwieGhyIiwiZW1pdCIsIl9hdXRoIiwidXNlciIsInBhc3MiLCJiYXNlNjRFbmNvZGVyIiwidHlwZSIsInVzZXJuYW1lIiwicGFzc3dvcmQiLCJ3aXRoQ3JlZGVudGlhbHMiLCJfd2l0aENyZWRlbnRpYWxzIiwicmVkaXJlY3RzIiwibiIsIl9tYXhSZWRpcmVjdHMiLCJtYXhSZXNwb25zZVNpemUiLCJUeXBlRXJyb3IiLCJfbWF4UmVzcG9uc2VTaXplIiwidG9KU09OIiwiZGF0YSIsImhlYWRlcnMiLCJzZW5kIiwiaXNPYmoiLCJfZm9ybURhdGEiLCJfaXNIb3N0Iiwic29ydFF1ZXJ5Iiwic29ydCIsIl9zb3J0IiwiX2ZpbmFsaXplUXVlcnlTdHJpbmciLCJxdWVyeSIsIl9xdWVyeSIsImpvaW4iLCJpbmRleCIsImluZGV4T2YiLCJxdWVyeUFyciIsInNsaWNlIiwic3BsaXQiLCJfYXBwZW5kUXVlcnlTdHJpbmciLCJfdGltZW91dEVycm9yIiwicmVhc29uIiwiZXJybm8iLCJjYWxsYmFjayIsIl9zZXRUaW1lb3V0cyIsInNldFRpbWVvdXQiXSwibWFwcGluZ3MiOiI7Ozs7QUFBQTs7O0FBR0EsSUFBTUEsUUFBUSxHQUFHQyxPQUFPLENBQUMsYUFBRCxDQUF4QjtBQUVBOzs7OztBQUlBQyxNQUFNLENBQUNDLE9BQVAsR0FBaUJDLFdBQWpCO0FBRUE7Ozs7OztBQU1BLFNBQVNBLFdBQVQsQ0FBcUJDLEdBQXJCLEVBQTBCO0FBQ3hCLE1BQUlBLEdBQUosRUFBUyxPQUFPQyxLQUFLLENBQUNELEdBQUQsQ0FBWjtBQUNWO0FBRUQ7Ozs7Ozs7OztBQVFBLFNBQVNDLEtBQVQsQ0FBZUQsR0FBZixFQUFvQjtBQUNsQixPQUFLLElBQU1FLEdBQVgsSUFBa0JI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LEVBRXJCLEtBQUtBLFFBRmdCLENBQXhCO0FBR0QsR0FSNkMsQ0FVOUM7OztBQUNBLE1BQUksS0FBS0MsZ0JBQUwsSUFBeUIsQ0FBQyxLQUFLYixxQkFBbkMsRUFBMEQ7QUFDeEQsU0FBS0EscUJBQUwsR0FBNkI0SCxVQUFVLENBQUMsWUFBTTtBQUM1QzFFLE1BQUFBLElBQUksQ0FBQ3FFLGFBQUwsQ0FDRSxzQkFERixFQUVFckUsSUFBSSxDQUFDckMsZ0JBRlAsRUFHRSxXQUhGO0FBS0QsS0FOc0MsRUFNcEMsS0FBS0EsZ0JBTitCLENBQXZDO0FBT0Q7QUFDRixDQXBCRCIsInNvdXJjZXNDb250ZW50IjpbIi8qKlxuICogTW9kdWxlIG9mIG1peGVkLWluIGZ1bmN0aW9ucyBzaGFyZWQgYmV0d2VlbiBub2RlIGFuZCBjbGllbnQgY29kZVxuICovXG5jb25zdCBpc09iamVjdCA9IHJlcXVpcmUoJy4vaXMtb2JqZWN0Jyk7XG5cbi8qKlxuICogRXhwb3NlIGBSZXF1ZXN0QmFzZWAuXG4gKi9cblxubW9kdWxlLmV4cG9ydHMgPSBSZXF1ZXN0QmFzZTtcblxuLyoqXG4gKiBJbml0aWFsaXplIGEgbmV3IGBSZXF1ZXN0QmFzZWAuXG4gKlxuICogQGFwaSBwdWJsaWNcbiAqL1xuXG5mdW5jdGlvbiBSZXF1ZXN0QmFzZShvYmopIHtcbiAgaWYgKG9iaikgcmV0dXJuIG1peGluKG9iaik7XG59XG5cbi8qKlxuICogTWl4aW4gdGhlIHByb3RvdHlwZSBwcm9wZXJ0aWVzLlxuICpcbiAqIEBwYXJhbSB7T2JqZWN0fSBvYmpcbiAqIEByZXR1cm4ge09iamVjdH1cbiAqIEBhcGkgcHJpdmF0ZVxuICovXG5cbmZ1bmN0aW9uIG1peGluKG9iaikge1xuICBmb3IgKGNvbnN0IGtleSBpbiBSZXF1ZXN0QmFzZS5wcm90b3R5cGUpIHtcbiAgICBpZiAoT2JqZWN0LnByb3RvdHlwZS5oYXNPd25Qcm9wZXJ0eS5jYWxsKFJlcXVlc3RCYXNlLnByb3RvdHlwZSwga2V5KSlcbiAgICAgIG9ialtrZXldID0gUmVxdWVzdEJhc2UucHJvdG90eXBlW2tleV07XG4gIH1cblxuICByZXR1cm4gb2JqO1xufVxuXG4vKipcbiAqIENsZWFyIHByZXZpb3VzIHRpbWVvdXQuXG4gKlxuICogQHJldHVybiB7UmVxdWVzdH0gZm9yIGNoYWluaW5nXG4gKiBAYXBpIHB1YmxpY1xuICovXG5cblJlcXVlc3RCYXNlLnByb3RvdHlwZS5jbGVhclRpbWVvdXQgPSBmdW5jdGlvbigpIHtcbiAgY2xlYXJUaW1lb3V0KHRoaXMuX3RpbWVyKTtcbiAgY2xlYXJUaW1lb3V0KHRoaXMuX3Jlc3BvbnNlVGltZW91dFRpbWVyKTtcbiAgY2xlYXJUaW1lb3V0KHRoaXMuX3VwbG9hZFRpbWVvdXRUaW1lcik7XG4gIGRlbGV0ZSB0aGlzLl90aW1lcjtcbiAgZGVsZXRlIHRoaXMuX3Jlc3BvbnNlVGltZW91dFRpbWVyO1xuICBkZWxldGUgdGhpcy5fdXBsb2FkVGltZW91dFRpbWVyO1xuICByZXR1cm4gdGhpcztcbn07XG5cbi8qKlxuICogT3ZlcnJpZGUgZGVmYXVsdCByZXNwb25zZSBib2R5IHBhcnNlclxuICpcbiAqIFRoaXMgZnVuY3Rpb24gd2lsbCBiZSBjYWxsZWQgdG8gY29udmVydCBpbmNvbWluZyBkYXRhIGludG8gcmVxdWVzdC5ib2R5XG4gKlxuICogQHBhcmFtIHtGdW5jdGlvbn1cbiAqIEBhcGkgcHVibGljXG4gKi9cblxuUmVxdWVzdEJhc2UucHJvdG90eXBlLnBhcnNlID0gZnVuY3Rpb24oZm4pIHtcbiAgdGhpcy5fcGFyc2VyID0gZm47XG4gIHJldHVybiB0aGlzO1xufTtcblxuLyoqXG4gKiBTZXQgZm9ybWF0IG9mIGJpbmFyeSByZXNwb25zZSBib2R5LlxuICogSW4gYnJvd3NlciB2YWxpZCBmb3JtYXRzIGFyZSAnYmxvYicgYW5kICdhcnJheWJ1ZmZlcicsXG4gKiB3aGljaCByZXR1cm4gQmxvYiBhbmQgQXJyYXlCdWZmZXIsIHJlc3BlY3RpdmVseS5cbiAqXG4gKiBJbiBOb2RlIGFsbCB2YWx1ZXMgcmVzdWx0IGluIEJ1ZmZlci5cbiAqXG4gKiBFeGFtcGxlczpcbiAqXG4gKiAgICAgIHJlcS5nZXQoJy8nKVxuICogICAgICAgIC5yZXNwb25zZVR5cGUoJ2Jsb2InKVxuICogICAgICAgIC5lbmQoY2FsbGJhY2spO1xuICpcbiAqIEBwYXJhbSB7U3RyaW5nfSB2YWxcbiAqIEByZXR1cm4ge1JlcXVlc3R9IGZvciBjaGFpbmluZ1xuICogQGFwaSBwdWJsaWNcbiAqL1xuXG5SZXF1ZXN0QmFzZS5wcm90b3R5cGUucmVzcG9uc2VUeXBlID0gZnVuY3Rpb24odmFsKSB7XG4gIHRoaXMuX3Jlc3BvbnNlVHlwZSA9IHZhbDtcbiAgcmV0dXJuIHRoaXM7XG59O1xuXG4vKipcbiAqIE92ZXJyaWRlIGRlZmF1bHQgcmVxdWVzdCBib2R5IHNlcmlhbGl6ZXJcbiAqXG4gKiBUaGlzIGZ1bmN0aW9uIHdpbGwgYmUgY2FsbGVkIHRvIGNvbnZlcnQgZGF0YSBzZXQgdmlhIC5zZW5kIG9yIC5hdHRhY2ggaW50byBwYXlsb2FkIHRvIHNlbmRcbiAqXG4gKiBAcGFyYW0ge0Z1bmN0aW9ufVxuICogQGFwaSBwdWJsaWNcbiAqL1xuXG5SZXF1ZXN0QmFzZS5wcm90b3R5cGUuc2VyaWFsaXplID0gZnVuY3Rpb24oZm4pIHtcbiAgdGhpcy5fc2VyaWFsaXplciA9IGZuO1xuICByZXR1cm4gdGhpcztcbn07XG5cbi8qKlxuICogU2V0IHRpbWVvdXRzLlxuICpcbiAqIC0gcmVzcG9uc2UgdGltZW91dCBpcyB0aW1lIGJldHdlZW4gc2VuZGluZyByZXF1ZXN0IGFuZCByZWNlaXZpbmcgdGhlIGZpcnN0IGJ5dGUgb2YgdGhlIHJlc3BvbnNlLiBJbmNsdWRlcyBETlMgYW5kIGNvbm5lY3Rpb24gdGltZS5cbiAqIC0gZGVhZGxpbmUgaXMgdGhlIHRpbWUgZnJvbSBzdGFydCBvZiB0aGUgcmVxdWVzdCB0byByZWNlaXZpbmcgcmVzcG9uc2UgYm9keSBpbiBmdWxsLiBJZiB0aGUgZGVhZGxpbmUgaXMgdG9vIHNob3J0IGxhcmdlIGZpbGVzIG1heSBub3QgbG9hZCBhdCBhbGwgb24gc2xvdyBjb25uZWN0aW9ucy5cbiAqIC0gdXBsb2FkIGlzIHRoZSB0aW1lICBzaW5jZSBsYXN0IGJpdCBvZiBkYXRhIHdhcyBzZW50IG9yIHJlY2VpdmVkLiBUaGlzIHRpbWVvdXQgd29ya3Mgb25seSBpZiBkZWFkbGluZSB0aW1lb3V0IGlzIG9mZlxuICpcbiAqIFZhbHVlIG9mIDAgb3IgZmFsc2UgbWVhbnMgbm8gdGltZW91dC5cbiAqXG4gKiBAcGFyYW0ge051bWJlcnxPYmplY3R9IG1zIG9yIHtyZXNwb25zZSwgZGVhZGxpbmV9XG4gKiBAcmV0dXJuIHtSZXF1ZXN0fSBmb3IgY2hhaW5pbmdcbiAqIEBhcGkgcHVibGljXG4gKi9cblxuUmVxdWVzdEJhc2UucHJvdG90eXBlLnRpbWVvdXQgPSBmdW5jdGlvbihvcHRpb25zKSB7XG4gIGlmICghb3B0aW9ucyB8fCB0eXBlb2Ygb3B0aW9ucyAhPT0gJ29iamVjdCcpIHtcbiAgICB0aGlzLl90aW1lb3V0ID0gb3B0aW9ucztcbiAgICB0aGlzLl9yZXNwb25zZVRpbWVvdXQgPSAwO1xuICAgIHRoaXMuX3VwbG9hZFRpbWVvdXQgPSAwO1xuICAgIHJldHVybiB0aGlzO1xuICB9XG5cbiAgZm9yIChjb25zdCBvcHRpb24gaW4gb3B0aW9ucykge1xuICAgIGlmIChPYmplY3QucHJvdG90eXBlLmhhc093blByb3BlcnR5LmNhbGwob3B0aW9ucywgb3B0aW9uKSkge1xuICAgICAgc3dpdGNoIChvcHRpb24pIHtcbiAgICAgICAgY2FzZSAnZGVhZGxpbmUnOlxuICAgICAgICAgIHRoaXMuX3RpbWVvdXQgPSBvcHRpb25zLmRlYWRsaW5lO1xuICAgICAgICAgIGJyZWFrO1xuICAgICAgICBjYXNlICdyZXNwb25zZSc6XG4gICAgICAgICAgdGhpcy5fcmVzcG9uc2VUaW1lb3V0ID0gb3B0aW9ucy5yZXNwb25zZTtcbiAgICAgICAgICBicmVhaztcbiAgICAgICAgY2FzZSAndXBsb2FkJzpcbiAgICAgICAgICB0aGlzLl91cGxvYWRUaW1lb3V0ID0gb3B0aW9ucy51cGxvYWQ7XG4gICAgICAgICAgYnJlYWs7XG4gICAgICAgIGRlZmF1bHQ6XG4gICAgICAgICAgY29uc29sZS53YXJuKCdVbmtub3duIHRpbWVvdXQgb3B0aW9uJywgb3B0aW9uKTtcbiAgICAgIH1cbiAgICB9XG4gIH1cblxuICByZXR1cm4gdGhpcztcbn07XG5cbi8qKlxuICogU2V0IG51bWJlciBvZiByZXRyeSBhdHRlbXB0cyBvbiBlcnJvci5cbiAqXG4gKiBGYWlsZWQgcmVxdWVzdHMgd2lsbCBiZSByZXRyaWVkICdjb3VudCcgdGltZXMgaWYgdGltZW91dCBvciBlcnIuY29kZSA+PSA1MDAuXG4gKlxuICogQHBhcmFtIHtOdW1iZXJ9IGNvdW50XG4gKiBAcGFyYW0ge0Z1bmN0aW9ufSBbZm5dXG4gKiBAcmV0dXJuIHtSZXF1ZXN0fSBmb3IgY2hhaW5pbmdcbiAqIEBhcGkgcHVibGljXG4gKi9cblxuUmVxdWVzdEJhc2UucHJvdG90eXBlLnJldHJ5ID0gZnVuY3Rpb24oY291bnQsIGZuKSB7XG4gIC8vIERlZmF1bHQgdG8gMSBpZiBubyBjb3VudCBwYXNzZWQgb3IgdHJ1ZVxuICBpZiAoYXJndW1lbnRzLmxlbmd0aCA9PT0gMCB8fCBjb3VudCA9PT0gdHJ1ZSkgY291bnQgPSAxO1xuICBpZiAoY291bnQgPD0gMCkgY291bnQgPSAwO1xuICB0aGlzLl9tYXhSZXRyaWVzID0gY291bnQ7XG4gIHRoaXMuX3JldHJpZXMgPSAwO1xuICB0aGlzLl9yZXRyeUNhbGxiYWNrID0gZm47XG4gIHJldHVybiB0aGlzO1xufTtcblxuY29uc3QgRVJST1JfQ09ERVMgPSBbJ0VDT05OUkVTRVQnLCAnRVRJTUVET1VUJywgJ0VBRERSSU5GTycsICdFU09DS0VUVElNRURPVVQnXTtcblxuLyoqXG4gKiBEZXRlcm1pbmUgaWYgYSByZXF1ZXN0IHNob3VsZCBiZSByZXRyaWVkLlxuICogKEJvcnJvd2VkIGZyb20gc2VnbWVudGlvL3N1cGVyYWdlbnQtcmV0cnkpXG4gKlxuICogQHBhcmFtIHtFcnJvcn0gZXJyIGFuIGVycm9yXG4gKiBAcGFyYW0ge1Jlc3BvbnNlfSBbcmVzXSByZXNwb25zZVxuICogQHJldHVybnMge0Jvb2xlYW59IGlmIHNlZ21lbnQgc2hvdWxkIGJlIHJldHJpZWRcbiAqL1xuUmVxdWVzdEJhc2UucHJvdG90eXBlLl9zaG91bGRSZXRyeSA9IGZ1bmN0aW9uKGVyciwgcmVzKSB7XG4gIGlmICghdGhpcy5fbWF4UmV0cmllcyB8fCB0aGlzLl9yZXRyaWVzKysgPj0gdGhpcy5fbWF4UmV0cmllcykge1xuICAgIHJldHVybiBmYWxzZTtcbiAgfVxuXG4gIGlmICh0aGlzLl9yZXRyeUNhbGxiYWNrKSB7XG4gICAgdHJ5IHtcbiAgICAgIGNvbnN0IG92ZXJyaWRlID0gdGhpcy5fcmV0cnlDYWxsYmFjayhlcnIsIHJlcyk7XG4gICAgICBpZiAob3ZlcnJpZGUgPT09IHRydWUpIHJldHVybiB0cnVlO1xuICAgICAgaWYgKG92ZXJyaWRlID09PSBmYWxzZSkgcmV0dXJuIGZhbHNlO1xuICAgICAgLy8gdW5kZWZpbmVkIGZhbGxzIGJhY2sgdG8gZGVmYXVsdHNcbiAgICB9IGNhdGNoIChlcnJfKSB7XG4gICAgICBjb25zb2xlLmVycm9yKGVycl8pO1xuICAgIH1cbiAgfVxuXG4gIGlmIChyZXMgJiYgcmVzLnN0YXR1cyAmJiByZXMuc3RhdHVzID49IDUwMCAmJiByZXMuc3RhdHVzICE9PSA1MDEpIHJldHVybiB0cnVlO1xuICBpZiAoZXJyKSB7XG4gICAgaWYgKGVyci5jb2RlICYmIEVSUk9SX0NPREVTLmluY2x1ZGVzKGVyci5jb2RlKSkgcmV0dXJuIHRydWU7XG4gICAgLy8gU3VwZXJhZ2VudCB0aW1lb3V0XG4gICAgaWYgKGVyci50aW1lb3V0ICYmIGVyci5jb2RlID09PSAnRUNPTk5BQk9SVEVEJykgcmV0dXJuIHRydWU7XG4gICAgaWYgKGVyci5jcm9zc0RvbWFpbikgcmV0dXJuIHRydWU7XG4gIH1cblxuICByZXR1cm4gZmFsc2U7XG59O1xuXG4vKipcbiAqIFJldHJ5IHJlcXVlc3RcbiAqXG4gKiBAcmV0dXJuIHtSZXF1ZXN0fSBmb3IgY2hhaW5pbmdcbiAqIEBhcGkgcHJpdmF0ZVxuICovXG5cblJlcXVlc3RCYXNlLnByb3RvdHlwZS5fcmV0cnkgPSBmdW5jdGlvbigpIHtcbiAgdGhpcy5jbGVhclRpbWVvdXQoKTtcblxuICAvLyBub2RlXG4gIGlmICh0aGlzLnJlcSkge1xuICAgIHRoaXMucmVxID0gbnVsbDtcbiAgICB0aGlzLnJlcSA9IHRoaXMucmVxdWVzdCgpO1xuICB9XG5cbiAgdGhpcy5fYWJvcnRlZCA9IGZhbHNlO1xuICB0aGlzLnRpbWVkb3V0ID0gZmFsc2U7XG4gIHRoaXMudGltZWRvdXRFcnJvciA9IG51bGw7XG5cbiAgcmV0dXJuIHRoaXMuX2VuZCgpO1xufTtcblxuLyoqXG4gKiBQcm9taXNlIHN1cHBvcnRcbiAqXG4gKiBAcGFyYW0ge0Z1bmN0aW9ufSByZXNvbHZlXG4gKiBAcGFyYW0ge0Z1bmN0aW9ufSBbcmVqZWN0XVxuICogQHJldHVybiB7UmVxdWVzdH1cbiAqL1xuXG5SZXF1ZXN0QmFzZS5wcm90b3R5cGUudGhlbiA9IGZ1bmN0aW9uKHJlc29sdmUsIHJlamVjdCkge1xuICBpZiAoIXRoaXMuX2Z1bGxmaWxsZWRQcm9taXNlKSB7XG4gICAgY29uc3Qgc2VsZiA9IHRoaXM7XG4gICAgaWYgKHRoaXMuX2VuZENhbGxlZCkge1xuICAgICAgY29uc29sZS53YXJuKFxuICAgICAgICAnV2FybmluZzogc3VwZXJhZ2VudCByZXF1ZXN0IHdhcyBzZW50IHR3aWNlLCBiZWNhdXNlIGJvdGggLmVuZCgpIGFuZCAudGhlbigpIHdlcmUgY2FsbGVkLiBOZXZlciBjYWxsIC5lbmQoKSBpZiB5b3UgdXNlIHByb21pc2VzJ1xuICAgICAgKTtcbiAgICB9XG5cbiAgICB0aGlzLl9mdWxsZmlsbGVkUHJvbWlzZSA9IG5ldyBQcm9taXNlKChyZXNvbHZlLCByZWplY3QpID0+IHtcbiAgICAgIHNlbGYub24oJ2Fib3J0JywgKCkgPT4ge1xuICAgICAgICBpZiAodGhpcy5fbWF4UmV0cmllcyAmJiB0aGlzLl9tYXhSZXRyaWVzID4gdGhpcy5fcmV0cmllcykge1xuICAgICAgICAgIHJldHVybjtcbiAgICAgICAgfVxuXG4gICAgICAgIGlmICh0aGlzLnRpbWVkb3V0ICYmIHRoaXMudGltZWRvdXRFcnJvcikge1xuICAgICAgICAgIHJlamVjdCh0aGlzLnRpbWVkb3V0RXJyb3IpO1xuICAgICAgICAgIHJldHVybjtcbiAgICAgICAgfVxuXG4gICAgICAgIGNvbnN0IGVyciA9IG5ldyBFcnJvcignQWJvcnRlZCcpO1xuICAgICAgICBlcnIuY29kZSA9ICdBQk9SVEVEJztcbiAgICAgICAgZXJyLnN0YXR1cyA9IHRoaXMuc3RhdHVzO1xuICAgICAgICBlcnIubWV0aG9kID0gdGhpcy5tZXRob2Q7XG4gICAgICAgIGVyci51cmwgPSB0aGlzLnVybDtcbiAgICAgICAgcmVqZWN0KGVycik7XG4gICAgICB9KTtcbiAgICAgIHNlbGYuZW5kKChlcnIsIHJlcykgPT4ge1xuICAgICAgICBpZiAoZXJyKSByZWplY3QoZXJyKTtcbiAgICAgICAgZWxzZSByZXNvbHZlKHJlcyk7XG4gICAgICB9KTtcbiAgICB9KTtcbiAgfVxuXG4gIHJldHVybiB0aGlzLl9mdWxsZmlsbGVkUHJvbWlzZS50aGVuKHJlc29sdmUsIHJlamVjdCk7XG59O1xuXG5SZXF1ZXN0QmFzZS5wcm90b3R5cGUuY2F0Y2ggPSBmdW5jdGlvbihjYikge1xuICByZXR1cm4gdGhpcy50aGVuKHVuZGVmaW5lZCwgY2IpO1xufTtcblxuLyoqXG4gKiBBbGxvdyBmb3IgZXh0ZW5zaW9uXG4gKi9cblxuUmVxdWVzdEJhc2UucHJvdG90eXBlLnVzZSA9IGZ1bmN0aW9uKGZuKSB7XG4gIGZuKHRoaXMpO1xuICByZXR1cm4gdGhpcztcbn07XG5cblJlcXVlc3RCYXNlLnByb3RvdHlwZS5vayA9IGZ1bmN0aW9uKGNiKSB7XG4gIGlmICh0eXBlb2YgY2IgIT09ICdmdW5jdGlvbicpIHRocm93IG5ldyBFcnJvcignQ2FsbGJhY2sgcmVxdWlyZWQnKTtcbiAgdGhpcy5fb2tDYWxsYmFjayA9IGNiO1xuICByZXR1cm4gdGhpcztcbn07XG5cblJlcXVlc3RCYXNlLnByb3RvdHlwZS5faXNSZXNwb25zZU9LID0gZnVuY3Rpb24ocmVzKSB7XG4gIGlmICghcmVzKSB7XG4gICAgcmV0dXJuIGZhbHNlO1xuICB9XG5cbiAgaWYgKHRoaXMuX29rQ2FsbGJhY2spIHtcbiAgICByZXR1cm4gdGhpcy5fb2tDYWxsYmFjayhyZXMpO1xuICB9XG5cbiAgcmV0dXJuIHJlcy5zdGF0dXMgPj0gMjAwICYmIHJlcy5zdGF0dXMgPCAzMDA7XG59O1xuXG4vKipcbiAqIEdldCByZXF1ZXN0IGhlYWRlciBgZmllbGRgLlxuICogQ2FzZS1pbnNlbnNpdGl2ZS5cbiAqXG4gKiBAcGFyYW0ge1N0cmluZ30gZmllbGRcbiAqIEByZXR1cm4ge1N0cmluZ31cbiAqIEBhcGkgcHVibGljXG4gKi9cblxuUmVxdWVzdEJhc2UucHJvdG90eXBlLmdldCA9IGZ1bmN0aW9uKGZpZWxkKSB7XG4gIHJldHVybiB0aGlzLl9oZWFkZXJbZmllbGQudG9Mb3dlckNhc2UoKV07XG59O1xuXG4vKipcbiAqIEdldCBjYXNlLWluc2Vuc2l0aXZlIGhlYWRlciBgZmllbGRgIHZhbHVlLlxuICogVGhpcyBpcyBhIGRlcHJlY2F0ZWQgaW50ZXJuYWwgQVBJLiBVc2UgYC5nZXQoZmllbGQpYCBpbnN0ZWFkLlxuICpcbiAqIChnZXRIZWFkZXIgaXMgbm8gbG9uZ2VyIHVzZWQgaW50ZXJuYWxseSBieSB0aGUgc3VwZXJhZ2VudCBjb2RlIGJhc2UpXG4gKlxuICogQHBhcmFtIHtTdHJpbmd9IGZpZWxkXG4gKiBAcmV0dXJuIHtTdHJpbmd9XG4gKiBAYXBpIHByaXZhdGVcbiAqIEBkZXByZWNhdGVkXG4gKi9cblxuUmVxdWVzdEJhc2UucHJvdG90eXBlLmdldEhlYWRlciA9IFJlcXVlc3RCYXNlLnByb3RvdHlwZS5nZXQ7XG5cbi8qKlxuICogU2V0IGhlYWRlciBgZmllbGRgIHRvIGB2YWxgLCBvciBtdWx0aXBsZSBmaWVsZHMgd2l0aCBvbmUgb2JqZWN0LlxuICogQ2FzZS1pbnNlbnNpdGl2ZS5cbiAqXG4gKiBFeGFtcGxlczpcbiAqXG4gKiAgICAgIHJlcS5nZXQoJy8nKVxuICogICAgICAgIC5zZXQoJ0FjY2VwdCcsICdhcHBsaWNhdGlvbi9qc29uJylcbiAqICAgICAgICAuc2V0KCdYLUFQSS1LZXknLCAnZm9vYmFyJylcbiAqICAgICAgICAuZW5kKGNhbGxiYWNrKTtcbiAqXG4gKiAgICAgIHJlcS5nZXQoJy8nKVxuICogICAgICAgIC5zZXQoeyBBY2NlcHQ6ICdhcHBsaWNhdGlvbi9qc29uJywgJ1gtQVBJLUtleSc6ICdmb29iYXInIH0pXG4gKiAgICAgICAgLmVuZChjYWxsYmFjayk7XG4gKlxuICogQHBhcmFtIHtTdHJpbmd8T2JqZWN0fSBmaWVsZFxuICogQHBhcmFtIHtTdHJpbmd9IHZhbFxuICogQHJldHVybiB7UmVxdWVzdH0gZm9yIGNoYWluaW5nXG4gKiBAYXBpIHB1YmxpY1xuICovXG5cblJlcXVlc3RCYXNlLnByb3RvdHlwZS5zZXQgPSBmdW5jdGlvbihmaWVsZCwgdmFsKSB7XG4gIGlmIChpc09iamVjdChmaWVsZCkpIHtcbiAgICBmb3IgKGNvbnN0IGtleSBpbiBmaWVsZCkge1xuICAgICAgaWYgKE9iamVjdC5wcm90b3R5cGUuaGFzT3duUHJvcGVydHkuY2FsbChmaWVsZCwga2V5KSlcbiAgICAgICAgdGhpcy5zZXQoa2V5LCBmaWVsZFtrZXldKTtcbiAgICB9XG5cbiAgICByZXR1cm4gdGhpcztcbiAgfVxuXG4gIHRoaXMuX2hlYWRlcltmaWVsZC50b0xvd2VyQ2FzZSgpXSA9IHZhbDtcbiAgdGhpcy5oZWFkZXJbZmllbGRdID0gdmFsO1xuICByZXR1cm4gdGhpcztcbn07XG5cbi8qKlxuICogUmVtb3ZlIGhlYWRlciBgZmllbGRgLlxuICogQ2FzZS1pbnNlbnNpdGl2ZS5cbiAqXG4gKiBFeGFtcGxlOlxuICpcbiAqICAgICAgcmVxLmdldCgnLycpXG4gKiAgICAgICAgLnVuc2V0KCdVc2VyLUFnZW50JylcbiAqICAgICAgICAuZW5kKGNhbGxiYWNrKTtcbiAqXG4gKiBAcGFyYW0ge1N0cmluZ30gZmllbGQgZmllbGQgbmFtZVxuICovXG5SZXF1ZXN0QmFzZS5wcm90b3R5cGUudW5zZXQgPSBmdW5jdGlvbihmaWVsZCkge1xuICBkZWxldGUgdGhpcy5faGVhZGVyW2ZpZWxkLnRvTG93ZXJDYXNlKCldO1xuICBkZWxldGUgdGhpcy5oZWFkZXJbZmllbGRdO1xuICByZXR1cm4gdGhpcztcbn07XG5cbi8qKlxuICogV3JpdGUgdGhlIGZpZWxkIGBuYW1lYCBhbmQgYHZhbGAsIG9yIG11bHRpcGxlIGZpZWxkcyB3aXRoIG9uZSBvYmplY3RcbiAqIGZvciBcIm11bHRpcGFydC9mb3JtLWRhdGFcIiByZXF1ZXN0IGJvZGllcy5cbiAqXG4gKiBgYGAganNcbiAqIHJlcXVlc3QucG9zdCgnL3VwbG9hZCcpXG4gKiAgIC5maWVsZCgnZm9vJywgJ2JhcicpXG4gKiAgIC5lbmQoY2FsbGJhY2spO1xuICpcbiAqIHJlcXVlc3QucG9zdCgnL3VwbG9hZCcpXG4gKiAgIC5maWVsZCh7IGZvbzogJ2JhcicsIGJhejogJ3F1eCcgfSlcbiAqICAgLmVuZChjYWxsYmFjayk7XG4gKiBgYGBcbiAqXG4gKiBAcGFyYW0ge1N0cmluZ3xPYmplY3R9IG5hbWUgbmFtZSBvZiBmaWVsZFxuICogQHBhcmFtIHtTdHJpbmd8QmxvYnxGaWxlfEJ1ZmZlcnxmcy5SZWFkU3RyZWFtfSB2YWwgdmFsdWUgb2YgZmllbGRcbiAqIEByZXR1cm4ge1JlcXVlc3R9IGZvciBjaGFpbmluZ1xuICogQGFwaSBwdWJsaWNcbiAqL1xuUmVxdWVzdEJhc2UucHJvdG90eXBlLmZpZWxkID0gZnVuY3Rpb24obmFtZSwgdmFsKSB7XG4gIC8vIG5hbWUgc2hvdWxkIGJlIGVpdGhlciBhIHN0cmluZyBvciBhbiBvYmplY3QuXG4gIGlmIChuYW1lID09PSBudWxsIHx8IHVuZGVmaW5lZCA9PT0gbmFtZSkge1xuICAgIHRocm93IG5ldyBFcnJvcignLmZpZWxkKG5hbWUsIHZhbCkgbmFtZSBjYW4gbm90IGJlIGVtcHR5Jyk7XG4gIH1cblxuICBpZiAodGhpcy5fZGF0YSkge1xuICAgIHRocm93IG5ldyBFcnJvcihcbiAgICAgIFwiLmZpZWxkKCkgY2FuJ3QgYmUgdXNlZCBpZiAuc2VuZCgpIGlzIHVzZWQuIFBsZWFzZSB1c2Ugb25seSAuc2VuZCgpIG9yIG9ubHkgLmZpZWxkKCkgJiAuYXR0YWNoKClcIlxuICAgICk7XG4gIH1cblxuICBpZiAoaXNPYmplY3QobmFtZSkpIHtcbiAgICBmb3IgKGNvbnN0IGtleSBpbiBuYW1lKSB7XG4gICAgICBpZiAoT2JqZWN0LnByb3RvdHlwZS5oYXNPd25Qcm9wZXJ0eS5jYWxsKG5hbWUsIGtleSkpXG4gICAgICAgIHRoaXMuZmllbGQoa2V5LCBuYW1lW2tleV0pO1xuICAgIH1cblxuICAgIHJldHVybiB0aGlzO1xuICB9XG5cbiAgaWYgKEFycmF5LmlzQXJyYXkodmFsKSkge1xuICAgIGZvciAoY29uc3QgaSBpbiB2YWwpIHtcbiAgICAgIGlmIChPYmplY3QucHJvdG90eXBlLmhhc093blByb3BlcnR5LmNhbGwodmFsLCBpKSlcbiAgICAgICAgdGhpcy5maWVsZChuYW1lLCB2YWxbaV0pO1xuICAgIH1cblxuICAgIHJldHVybiB0aGlzO1xuICB9XG5cbiAgLy8gdmFsIHNob3VsZCBiZSBkZWZpbmVkIG5vd1xuICBpZiAodmFsID09PSBudWxsIHx8IHVuZGVmaW5lZCA9PT0gdmFsKSB7XG4gICAgdGhyb3cgbmV3IEVycm9yKCcuZmllbGQobmFtZSwgdmFsKSB2YWwgY2FuIG5vdCBiZSBlbXB0eScpO1xuICB9XG5cbiAgaWYgKHR5cGVvZiB2YWwgPT09ICdib29sZWFuJykge1xuICAgIHZhbCA9IFN0cmluZyh2YWwpO1xuICB9XG5cbiAgdGhpcy5fZ2V0Rm9ybURhdGEoKS5hcHBlbmQobmFtZSwgdmFsKTtcbiAgcmV0dXJuIHRoaXM7XG59O1xuXG4vKipcbiAqIEFib3J0IHRoZSByZXF1ZXN0LCBhbmQgY2xlYXIgcG90ZW50aWFsIHRpbWVvdXQuXG4gKlxuICogQHJldHVybiB7UmVxdWVzdH0gcmVxdWVzdFxuICogQGFwaSBwdWJsaWNcbiAqL1xuUmVxdWVzdEJhc2UucHJvdG90eXBlLmFib3J0ID0gZnVuY3Rpb24oKSB7XG4gIGlmICh0aGlzLl9hYm9ydGVkKSB7XG4gICAgcmV0dXJuIHRoaXM7XG4gIH1cblxuICB0aGlzLl9hYm9ydGVkID0gdHJ1ZTtcbiAgaWYgKHRoaXMueGhyKSB0aGlzLnhoci5hYm9ydCgpOyAvLyBicm93c2VyXG4gIGlmICh0aGlzLnJlcSkgdGhpcy5yZXEuYWJvcnQoKTsgLy8gbm9kZVxuICB0aGlzLmNsZWFyVGltZW91dCgpO1xuICB0aGlzLmVtaXQoJ2Fib3J0Jyk7XG4gIHJldHVybiB0aGlzO1xufTtcblxuUmVxdWVzdEJhc2UucHJvdG90eXBlLl9hdXRoID0gZnVuY3Rpb24odXNlciwgcGFzcywgb3B0aW9ucywgYmFzZTY0RW5jb2Rlcikge1xuICBzd2l0Y2ggKG9wdGlvbnMudHlwZSkge1xuICAgIGNhc2UgJ2Jhc2ljJzpcbiAgICAgIHRoaXMuc2V0KCdBdXRob3JpemF0aW9uJywgYEJhc2ljICR7YmFzZTY0RW5jb2RlcihgJHt1c2VyfToke3Bhc3N9YCl9YCk7XG4gICAgICBicmVhaztcblxuICAgIGNhc2UgJ2F1dG8nOlxuICAgICAgdGhpcy51c2VybmFtZSA9IHVzZXI7XG4gICAgICB0aGlzLnBhc3N3b3JkID0gcGFzcztcbiAgICAgIGJyZWFrO1xuXG4gICAgY2FzZSAnYmVhcmVyJzogLy8gdXNhZ2Ugd291bGQgYmUgLmF1dGgoYWNjZXNzVG9rZW4sIHsgdHlwZTogJ2JlYXJlcicgfSlcbiAgICAgIHRoaXMuc2V0KCdBdXRob3JpemF0aW9uJywgYEJlYXJlciAke3VzZXJ9YCk7XG4gICAgICBicmVhaztcbiAgICBkZWZhdWx0OlxuICAgICAgYnJlYWs7XG4gIH1cblxuICByZXR1cm4gdGhpcztcbn07XG5cbi8qKlxuICogRW5hYmxlIHRyYW5zbWlzc2lvbiBvZiBjb29raWVzIHdpdGggeC1kb21haW4gcmVxdWVzdHMuXG4gKlxuICogTm90ZSB0aGF0IGZvciB0aGlzIHRvIHdvcmsgdGhlIG9yaWdpbiBtdXN0IG5vdCBiZVxuICogdXNpbmcgXCJBY2Nlc3MtQ29udHJvbC1BbGxvdy1PcmlnaW5cIiB3aXRoIGEgd2lsZGNhcmQsXG4gKiBhbmQgYWxzbyBtdXN0IHNldCBcIkFjY2Vzcy1Db250cm9sLUFsbG93LUNyZWRlbnRpYWxzXCJcbiAqIHRvIFwidHJ1ZVwiLlxuICpcbiAqIEBhcGkgcHVibGljXG4gKi9cblxuUmVxdWVzdEJhc2UucHJvdG90eXBlLndpdGhDcmVkZW50aWFscyA9IGZ1bmN0aW9uKG9uKSB7XG4gIC8vIFRoaXMgaXMgYnJvd3Nlci1vbmx5IGZ1bmN0aW9uYWxpdHkuIE5vZGUgc2lkZSBpcyBuby1vcC5cbiAgaWYgKG9uID09PSB1bmRlZmluZWQpIG9uID0gdHJ1ZTtcbiAgdGhpcy5fd2l0aENyZWRlbnRpYWxzID0gb247XG4gIHJldHVybiB0aGlzO1xufTtcblxuLyoqXG4gKiBTZXQgdGhlIG1heCByZWRpcmVjdHMgdG8gYG5gLiBEb2VzIG5vdGhpbmcgaW4gYnJvd3NlciBYSFIgaW1wbGVtZW50YXRpb24uXG4gKlxuICogQHBhcmFtIHtOdW1iZXJ9IG5cbiAqIEByZXR1cm4ge1JlcXVlc3R9IGZvciBjaGFpbmluZ1xuICogQGFwaSBwdWJsaWNcbiAqL1xuXG5SZXF1ZXN0QmFzZS5wcm90b3R5cGUucmVkaXJlY3RzID0gZnVuY3Rpb24obikge1xuICB0aGlzLl9tYXhSZWRpcmVjdHMgPSBuO1xuICByZXR1cm4gdGhpcztcbn07XG5cbi8qKlxuICogTWF4aW11bSBzaXplIG9mIGJ1ZmZlcmVkIHJlc3BvbnNlIGJvZHksIGluIGJ5dGVzLiBDb3VudHMgdW5jb21wcmVzc2VkIHNpemUuXG4gKiBEZWZhdWx0IDIwME1CLlxuICpcbiAqIEBwYXJhbSB7TnVtYmVyfSBuIG51bWJlciBvZiBieXRlc1xuICogQHJldHVybiB7UmVxdWVzdH0gZm9yIGNoYWluaW5nXG4gKi9cblJlcXVlc3RCYXNlLnByb3RvdHlwZS5tYXhSZXNwb25zZVNpemUgPSBmdW5jdGlvbihuKSB7XG4gIGlmICh0eXBlb2YgbiAhPT0gJ251bWJlcicpIHtcbiAgICB0aHJvdyBuZXcgVHlwZUVycm9yKCdJbnZhbGlkIGFyZ3VtZW50Jyk7XG4gIH1cblxuICB0aGlzLl9tYXhSZXNwb25zZVNpemUgPSBuO1xuICByZXR1cm4gdGhpcztcbn07XG5cbi8qKlxuICogQ29udmVydCB0byBhIHBsYWluIGphdmFzY3JpcHQgb2JqZWN0IChub3QgSlNPTiBzdHJpbmcpIG9mIHNjYWxhciBwcm9wZXJ0aWVzLlxuICogTm90ZSBhcyB0aGlzIG1ldGhvZCBpcyBkZXNpZ25lZCB0byByZXR1cm4gYSB1c2VmdWwgbm9uLXRoaXMgdmFsdWUsXG4gKiBpdCBjYW5ub3QgYmUgY2hhaW5lZC5cbiAqXG4gKiBAcmV0dXJuIHtPYmplY3R9IGRlc2NyaWJpbmcgbWV0aG9kLCB1cmwsIGFuZCBkYXRhIG9mIHRoaXMgcmVxdWVzdFxuICogQGFwaSBwdWJsaWNcbiAqL1xuXG5SZXF1ZXN0QmFzZS5wcm90b3R5cGUudG9KU09OID0gZnVuY3Rpb24oKSB7XG4gIHJldHVybiB7XG4gICAgbWV0aG9kOiB0aGlzLm1ldGhvZCxcbiAgICB1cmw6IHRoaXMudXJsLFxuICAgIGRhdGE6IHRoaXMuX2RhdGEsXG4gICAgaGVhZGVyczogdGhpcy5faGVhZGVyXG4gIH07XG59O1xuXG4vKipcbiAqIFNlbmQgYGRhdGFgIGFzIHRoZSByZXF1ZXN0IGJvZHksIGRlZmF1bHRpbmcgdGhlIGAudHlwZSgpYCB0byBcImpzb25cIiB3aGVuXG4gKiBhbiBvYmplY3QgaXMgZ2l2ZW4uXG4gKlxuICogRXhhbXBsZXM6XG4gKlxuICogICAgICAgLy8gbWFudWFsIGpzb25cbiAqICAgICAgIHJlcXVlc3QucG9zdCgnL3VzZXInKVxuICogICAgICAgICAudHlwZSgnanNvbicpXG4gKiAgICAgICAgIC5zZW5kKCd7XCJuYW1lXCI6XCJ0alwifScpXG4gKiAgICAgICAgIC5lbmQoY2FsbGJhY2spXG4gKlxuICogICAgICAgLy8gYXV0byBqc29uXG4gKiAgICAgICByZXF1ZXN0LnBvc3QoJy91c2VyJylcbiAqICAgICAgICAgLnNlbmQoeyBuYW1lOiAndGonIH0pXG4gKiAgICAgICAgIC5lbmQoY2FsbGJhY2spXG4gKlxuICogICAgICAgLy8gbWFudWFsIHgtd3d3LWZvcm0tdXJsZW5jb2RlZFxuICogICAgICAgcmVxdWVzdC5wb3N0KCcvdXNlcicpXG4gKiAgICAgICAgIC50eXBlKCdmb3JtJylcbiAqICAgICAgICAgLnNlbmQoJ25hbWU9dGonKVxuICogICAgICAgICAuZW5kKGNhbGxiYWNrKVxuICpcbiAqICAgICAgIC8vIGF1dG8geC13d3ctZm9ybS11cmxlbmNvZGVkXG4gKiAgICAgICByZXF1ZXN0LnBvc3QoJy91c2VyJylcbiAqICAgICAgICAgLnR5cGUoJ2Zvcm0nKVxuICogICAgICAgICAuc2VuZCh7IG5hbWU6ICd0aicgfSlcbiAqICAgICAgICAgLmVuZChjYWxsYmFjaylcbiAqXG4gKiAgICAgICAvLyBkZWZhdWx0cyB0byB4LXd3dy1mb3JtLXVybGVuY29kZWRcbiAqICAgICAgcmVxdWVzdC5wb3N0KCcvdXNlcicpXG4gKiAgICAgICAgLnNlbmQoJ25hbWU9dG9iaScpXG4gKiAgICAgICAgLnNlbmQoJ3NwZWNpZXM9ZmVycmV0JylcbiAqICAgICAgICAuZW5kKGNhbGxiYWNrKVxuICpcbiAqIEBwYXJhbSB7U3RyaW5nfE9iamVjdH0gZGF0YVxuICogQHJldHVybiB7UmVxdWVzdH0gZm9yIGNoYWluaW5nXG4gKiBAYXBpIHB1YmxpY1xuICovXG5cbi8vIGVzbGludC1kaXNhYmxlLW5leHQtbGluZSBjb21wbGV4aXR5XG5SZXF1ZXN0QmFzZS5wcm90b3R5cGUuc2VuZCA9IGZ1bmN0aW9uKGRhdGEpIHtcbiAgY29uc3QgaXNPYmogPSBpc09iamVjdChkYXRhKTtcbiAgbGV0IHR5cGUgPSB0aGlzLl9oZWFkZXJbJ2NvbnRlbnQtdHlwZSddO1xuXG4gIGlmICh0aGlzLl9mb3JtRGF0YSkge1xuICAgIHRocm93IG5ldyBFcnJvcihcbiAgICAgIFwiLnNlbmQoKSBjYW4ndCBiZSB1c2VkIGlmIC5hdHRhY2goKSBvciAuZmllbGQoKSBpcyB1c2VkLiBQbGVhc2UgdXNlIG9ubHkgLnNlbmQoKSBvciBvbmx5IC5maWVsZCgpICYgLmF0dGFjaCgpXCJcbiAgICApO1xuICB9XG5cbiAgaWYgKGlzT2JqICYmICF0aGlzLl9kYXRhKSB7XG4gICAgaWYgKEFycmF5LmlzQXJyYXkoZGF0YSkpIHtcbiAgICAgIHRoaXMuX2RhdGEgPSBbXTtcbiAgICB9IGVsc2UgaWYgKCF0aGlzLl9pc0hvc3QoZGF0YSkpIHtcbiAgICAgIHRoaXMuX2RhdGEgPSB7fTtcbiAgICB9XG4gIH0gZWxzZSBpZiAoZGF0YSAmJiB0aGlzLl9kYXRhICYmIHRoaXMuX2lzSG9zdCh0aGlzLl9kYXRhKSkge1xuICAgIHRocm93IG5ldyBFcnJvcihcIkNhbid0IG1lcmdlIHRoZXNlIHNlbmQgY2FsbHNcIik7XG4gIH1cblxuICAvLyBtZXJnZVxuICBpZiAoaXNPYmogJiYgaXNPYmplY3QodGhpcy5fZGF0YSkpIHtcbiAgICBmb3IgKGNvbnN0IGtleSBpbiBkYXRhKSB7XG4gICAgICBpZiAoT2JqZWN0LnByb3RvdHlwZS5oYXNPd25Qcm9wZXJ0eS5jYWxsKGRhdGEsIGtleSkpXG4gICAgICAgIHRoaXMuX2RhdGFba2V5XSA9IGRhdGFba2V5XTtcbiAgICB9XG4gIH0gZWxzZSBpZiAodHlwZW9mIGRhdGEgPT09ICdzdHJpbmcnKSB7XG4gICAgLy8gZGVmYXVsdCB0byB4LXd3dy1mb3JtLXVybGVuY29kZWRcbiAgICBpZiAoIXR5cGUpIHRoaXMudHlwZSgnZm9ybScpO1xuICAgIHR5cGUgPSB0aGlzLl9oZWFkZXJbJ2NvbnRlbnQtdHlwZSddO1xuICAgIGlmICh0eXBlID09PSAnYXBwbGljYXRpb24veC13d3ctZm9ybS11cmxlbmNvZGVkJykge1xuICAgICAgdGhpcy5fZGF0YSA9IHRoaXMuX2RhdGEgPyBgJHt0aGlzLl9kYXRhfSYke2RhdGF9YCA6IGRhdGE7XG4gICAgfSBlbHNlIHtcbiAgICAgIHRoaXMuX2RhdGEgPSAodGhpcy5fZGF0YSB8fCAnJykgKyBkYXRhO1xuICAgIH1cbiAgfSBlbHNlIHtcbiAgICB0aGlzLl9kYXRhID0gZGF0YTtcbiAgfVxuXG4gIGlmICghaXNPYmogfHwgdGhpcy5faXNIb3N0KGRhdGEpKSB7XG4gICAgcmV0dXJuIHRoaXM7XG4gIH1cblxuICAvLyBkZWZhdWx0IHRvIGpzb25cbiAgaWYgKCF0eXBlKSB0aGlzLnR5cGUoJ2pzb24nKTtcbiAgcmV0dXJuIHRoaXM7XG59O1xuXG4vKipcbiAqIFNvcnQgYHF1ZXJ5c3RyaW5nYCBieSB0aGUgc29ydCBmdW5jdGlvblxuICpcbiAqXG4gKiBFeGFtcGxlczpcbiAqXG4gKiAgICAgICAvLyBkZWZhdWx0IG9yZGVyXG4gKiAgICAgICByZXF1ZXN0LmdldCgnL3VzZXInKVxuICogICAgICAgICAucXVlcnkoJ25hbWU9TmljaycpXG4gKiAgICAgICAgIC5xdWVyeSgnc2VhcmNoPU1hbm55JylcbiAqICAgICAgICAgLnNvcnRRdWVyeSgpXG4gKiAgICAgICAgIC5lbmQoY2FsbGJhY2spXG4gKlxuICogICAgICAgLy8gY3VzdG9taXplZCBzb3J0IGZ1bmN0aW9uXG4gKiAgICAgICByZXF1ZXN0LmdldCgnL3VzZXInKVxuICogICAgICAgICAucXVlcnkoJ25hbWU9TmljaycpXG4gKiAgICAgICAgIC5xdWVyeSgnc2VhcmNoPU1hbm55JylcbiAqICAgICAgICAgLnNvcnRRdWVyeShmdW5jdGlvbihhLCBiKXtcbiAqICAgICAgICAgICByZXR1cm4gYS5sZW5ndGggLSBiLmxlbmd0aDtcbiAqICAgICAgICAgfSlcbiAqICAgICAgICAgLmVuZChjYWxsYmFjaylcbiAqXG4gKlxuICogQHBhcmFtIHtGdW5jdGlvbn0gc29ydFxuICogQHJldHVybiB7UmVxdWVzdH0gZm9yIGNoYWluaW5nXG4gKiBAYXBpIHB1YmxpY1xuICovXG5cblJlcXVlc3RCYXNlLnByb3RvdHlwZS5zb3J0UXVlcnkgPSBmdW5jdGlvbihzb3J0KSB7XG4gIC8vIF9zb3J0IGRlZmF1bHQgdG8gdHJ1ZSBidXQgb3RoZXJ3aXNlIGNhbiBiZSBhIGZ1bmN0aW9uIG9yIGJvb2xlYW5cbiAgdGhpcy5fc29ydCA9IHR5cGVvZiBzb3J0ID09PSAndW5kZWZpbmVkJyA/IHRydWUgOiBzb3J0O1xuICByZXR1cm4gdGhpcztcbn07XG5cbi8qKlxuICogQ29tcG9zZSBxdWVyeXN0cmluZyB0byBhcHBlbmQgdG8gcmVxLnVybFxuICpcbiAqIEBhcGkgcHJpdmF0ZVxuICovXG5SZXF1ZXN0QmFzZS5wcm90b3R5cGUuX2ZpbmFsaXplUXVlcnlTdHJpbmcgPSBmdW5jdGlvbigpIHtcbiAgY29uc3QgcXVlcnkgPSB0aGlzLl9xdWVyeS5qb2luKCcmJyk7XG4gIGlmIChxdWVyeSkge1xuICAgIHRoaXMudXJsICs9ICh0aGlzLnVybC5pbmNsdWRlcygnPycpID8gJyYnIDogJz8nKSArIHF1ZXJ5O1xuICB9XG5cbiAgdGhpcy5fcXVlcnkubGVuZ3RoID0gMDsgLy8gTWFrZXMgdGhlIGNhbGwgaWRlbXBvdGVudFxuXG4gIGlmICh0aGlzLl9zb3J0KSB7XG4gICAgY29uc3QgaW5kZXggPSB0aGlzLnVybC5pbmRleE9mKCc/Jyk7XG4gICAgaWYgKGluZGV4ID49IDApIHtcbiAgICAgIGNvbnN0IHF1ZXJ5QXJyID0gdGhpcy51cmwuc2xpY2UoaW5kZXggKyAxKS5zcGxpdCgnJicpO1xuICAgICAgaWYgKHR5cGVvZiB0aGlzLl9zb3J0ID09PSAnZnVuY3Rpb24nKSB7XG4gICAgICAgIHF1ZXJ5QXJyLnNvcnQodGhpcy5fc29ydCk7XG4gICAgICB9IGVsc2Uge1xuICAgICAgICBxdWVyeUFyci5zb3J0KCk7XG4gICAgICB9XG5cbiAgICAgIHRoaXMudXJsID0gdGhpcy51cmwuc2xpY2UoMCwgaW5kZXgpICsgJz8nICsgcXVlcnlBcnIuam9pbignJicpO1xuICAgIH1cbiAgfVxufTtcblxuLy8gRm9yIGJhY2t3YXJkcyBjb21wYXQgb25seVxuUmVxdWVzdEJhc2UucHJvdG90eXBlLl9hcHBlbmRRdWVyeVN0cmluZyA9ICgpID0+IHtcbiAgY29uc29sZS53YXJuKCdVbnN1cHBvcnRlZCcpO1xufTtcblxuLyoqXG4gKiBJbnZva2UgY2FsbGJhY2sgd2l0aCB0aW1lb3V0IGVycm9yLlxuICpcbiAqIEBhcGkgcHJpdmF0ZVxuICovXG5cblJlcXVlc3RCYXNlLnByb3RvdHlwZS5fdGltZW91dEVycm9yID0gZnVuY3Rpb24ocmVhc29uLCB0aW1lb3V0LCBlcnJubykge1xuICBpZiAodGhpcy5fYWJvcnRlZCkge1xuICAgIHJldHVybjtcbiAgfVxuXG4gIGNvbnN0IGVyciA9IG5ldyBFcnJvcihgJHtyZWFzb24gKyB0aW1lb3V0fW1zIGV4Y2VlZGVkYCk7XG4gIGVyci50aW1lb3V0ID0gdGltZW91dDtcbiAgZXJyLmNvZGUgPSAnRUNPTk5BQk9SVEVEJztcbiAgZXJyLmVycm5vID0gZXJybm87XG4gIHRoaXMudGltZWRvdXQgPSB0cnVlO1xuICB0aGlzLnRpbWVkb3V0RXJyb3IgPSBlcnI7XG4gIHRoaXMuYWJvcnQoKTtcbiAgdGhpcy5jYWxsYmFjayhlcnIpO1xufTtcblxuUmVxdWVzdEJhc2UucHJvdG90eXBlLl9zZXRUaW1lb3V0cyA9IGZ1bmN0aW9uKCkge1xuICBjb25zdCBzZWxmID0gdGhpcztcblxuICAvLyBkZWFkbGluZVxuICBpZiAodGhpcy5fdGltZW91dCAmJiAhdGhpcy5fdGltZXIpIHtcbiAgICB0aGlzLl90aW1lciA9IHNldFRpbWVvdXQoKCkgPT4ge1xuICAgICAgc2VsZi5fdGltZW91dEVycm9yKCdUaW1lb3V0IG9mICcsIHNlbGYuX3RpbWVvdXQsICdFVElNRScpO1xuICAgIH0sIHRoaXMuX3RpbWVvdXQpO1xuICB9XG5cbiAgLy8gcmVzcG9uc2UgdGltZW91dFxuICBpZiAodGhpcy5fcmVzcG9uc2VUaW1lb3V0ICYmICF0aGlzLl9yZXNwb25zZVRpbWVvdXRUaW1lcikge1xuICAgIHRoaXMuX3Jlc3BvbnNlVGltZW91dFRpbWVyID0gc2V0VGltZW91dCgoKSA9PiB7XG4gICAgICBzZWxmLl90aW1lb3V0RXJyb3IoXG4gICAgICAgICdSZXNwb25zZSB0aW1lb3V0IG9mICcsXG4gICAgICAgIHNlbGYuX3Jlc3BvbnNlVGltZW91dCxcbiAgICAgICAgJ0VUSU1FRE9VVCdcbiAgICAgICk7XG4gICAgfSwgdGhpcy5fcmVzcG9uc2VUaW1lb3V0KTtcbiAgfVxufTtcbiJdfQ==
}, function(modId) { var map = {"./is-object":1603008214469}; return __REQUIRE__(map[modId], modId); })
__DEFINE__(1603008214469, function(require, module, exports) {


function _typeof(obj) { "@babel/helpers - typeof"; if (typeof Symbol === "function" && typeof Symbol.iterator === "symbol") { _typeof = function _typeof(obj) { return typeof obj; }; } else { _typeof = function _typeof(obj) { return obj && typeof Symbol === "function" && obj.constructor === Symbol && obj !== Symbol.prototype ? "symbol" : typeof obj; }; } return _typeof(obj); }

/**
 * Check if `obj` is an object.
 *
 * @param {Object} obj
 * @return {Boolean}
 * @api private
 */
function isObject(obj) {
  return obj !== null && _typeof(obj) === 'object';
}

module.exports = isObject;
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbIi4uL3NyYy9pcy1vYmplY3QuanMiXSwibmFtZXMiOlsiaXNPYmplY3QiLCJvYmoiLCJtb2R1bGUiLCJleHBvcnRzIl0sIm1hcHBpbmdzIjoiOzs7O0FBQUE7Ozs7Ozs7QUFRQSxTQUFTQSxRQUFULENBQWtCQyxHQUFsQixFQUF1QjtBQUNyQixTQUFPQSxHQUFHLEtBQUssSUFBUixJQUFnQixRQUFPQSxHQUFQLE1BQWUsUUFBdEM7QUFDRDs7QUFFREMsTUFBTSxDQUFDQyxPQUFQLEdBQWlCSCxRQUFqQiIsInNvdXJjZXNDb250ZW50IjpbIi8qKlxuICogQ2hlY2sgaWYgYG9iamAgaXMgYW4gb2JqZWN0LlxuICpcbiAqIEBwYXJhbSB7T2JqZWN0fSBvYmpcbiAqIEByZXR1cm4ge0Jvb2xlYW59XG4gKiBAYXBpIHByaXZhdGVcbiAqL1xuXG5mdW5jdGlvbiBpc09iamVjdChvYmopIHtcbiAgcmV0dXJuIG9iaiAhPT0gbnVsbCAmJiB0eXBlb2Ygb2JqID09PSAnb2JqZWN0Jztcbn1cblxubW9kdWxlLmV4cG9ydHMgPSBpc09iamVjdDtcbiJdfQ==
}, function(modId) { var map = {}; return __REQUIRE__(map[modId], modId); })
__DEFINE__(1603008214470, function(require, module, exports) {


/**
 * Module dependencies.
 */
var _require = require('string_decoder'),
    StringDecoder = _require.StringDecoder;

var Stream = require('stream');

var zlib = require('zlib');
/**
 * Buffers response data events and re-emits when they're unzipped.
 *
 * @param {Request} req
 * @param {Response} res
 * @api private
 */


exports.unzip = function (req, res) {
  var unzip = zlib.createUnzip();
  var stream = new Stream();
  var decoder; // make node responseOnEnd() happy

  stream.req = req;
  unzip.on('error', function (err) {
    if (err && err.code === 'Z_BUF_ERROR') {
      // unexpected end of file is ignored by browsers and curl
      stream.emit('end');
      return;
    }

    stream.emit('error', err);
  }); // pipe to unzip

  res.pipe(unzip); // override `setEncoding` to capture encoding

  res.setEncoding = function (type) {
    decoder = new StringDecoder(type);
  }; // decode upon decompressing with captured encoding


  unzip.on('data', function (buf) {
    if (decoder) {
      var str = decoder.write(buf);
      if (str.length > 0) stream.emit('data', str);
    } else {
      stream.emit('data', buf);
    }
  });
  unzip.on('end', function () {
    stream.emit('end');
  }); // override `on` to capture data listeners

  var _on = res.on;

  res.on = function (type, fn) {
    if (type === 'data' || type === 'end') {
      stream.on(type, fn.bind(res));
    } else if (type === 'error') {
      stream.on(type, fn.bind(res));

      _on.call(res, type, fn);
    } else {
      _on.call(res, type, fn);
    }

    return this;
  };
};
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbIi4uLy4uL3NyYy9ub2RlL3VuemlwLmpzIl0sIm5hbWVzIjpbInJlcXVpcmUiLCJTdHJpbmdEZWNvZGVyIiwiU3RyZWFtIiwiemxpYiIsImV4cG9ydHMiLCJ1bnppcCIsInJlcSIsInJlcyIsImNyZWF0ZVVuemlwIiwic3RyZWFtIiwiZGVjb2RlciIsIm9uIiwiZXJyIiwiY29kZSIsImVtaXQiLCJwaXBlIiwic2V0RW5jb2RpbmciLCJ0eXBlIiwiYnVmIiwic3RyIiwid3JpdGUiLCJsZW5ndGgiLCJfb24iLCJmbiIsImJpbmQiLCJjYWxsIl0sIm1hcHBpbmdzIjoiOztBQUFBOzs7ZUFJMEJBLE9BQU8sQ0FBQyxnQkFBRCxDO0lBQXpCQyxhLFlBQUFBLGE7O0FBQ1IsSUFBTUMsTUFBTSxHQUFHRixPQUFPLENBQUMsUUFBRCxDQUF0Qjs7QUFDQSxJQUFNRyxJQUFJLEdBQUdILE9BQU8sQ0FBQyxNQUFELENBQXBCO0FBRUE7Ozs7Ozs7OztBQVFBSSxPQUFPLENBQUNDLEtBQVIsR0FBZ0IsVUFBQ0MsR0FBRCxFQUFNQyxHQUFOLEVBQWM7QUFDNUIsTUFBTUYsS0FBSyxHQUFHRixJQUFJLENBQUNLLFdBQUwsRUFBZDtBQUNBLE1BQU1DLE1BQU0sR0FBRyxJQUFJUCxNQUFKLEVBQWY7QUFDQSxNQUFJUSxPQUFKLENBSDRCLENBSzVCOztBQUNBRCxFQUFBQSxNQUFNLENBQUNILEdBQVAsR0FBYUEsR0FBYjtBQUVBRCxFQUFBQSxLQUFLLENBQUNNLEVBQU4sQ0FBUyxPQUFULEVBQWtCLFVBQUFDLEdBQUcsRUFBSTtBQUN2QixRQUFJQSxHQUFHLElBQUlBLEdBQUcsQ0FBQ0MsSUFBSixLQUFhLGFBQXhCLEVBQXVDO0FBQ3JDO0FBQ0FKLE1BQUFBLE1BQU0sQ0FBQ0ssSUFBUCxDQUFZLEtBQVo7QUFDQTtBQUNEOztBQUVETCxJQUFBQSxNQUFNLENBQUNLLElBQVAsQ0FBWSxPQUFaLEVBQXFCRixHQUFyQjtBQUNELEdBUkQsRUFSNEIsQ0FrQjVCOztBQUNBTCxFQUFBQSxHQUFHLENBQUNRLElBQUosQ0FBU1YsS0FBVCxFQW5CNEIsQ0FxQjVCOztBQUNBRSxFQUFBQSxHQUFHLENBQUNTLFdBQUosR0FBa0IsVUFBQUMsSUFBSSxFQUFJO0FBQ3hCUCxJQUFBQSxPQUFPLEdBQUcsSUFBSVQsYUFBSixDQUFrQmdCLElBQWxCLENBQVY7QUFDRCxHQUZELENBdEI0QixDQTBCNUI7OztBQUNBWixFQUFBQSxLQUFLLENBQUNNLEVBQU4sQ0FBUyxNQUFULEVBQWlCLFVBQUFPLEdBQUcsRUFBSTtBQUN0QixRQUFJUixPQUFKLEVBQWE7QUFDWCxVQUFNUyxHQUFHLEdBQUdULE9BQU8sQ0FBQ1UsS0FBUixDQUFjRixHQUFkLENBQVo7QUFDQSxVQUFJQyxHQUFHLENBQUNFLE1BQUosR0FBYSxDQUFqQixFQUFvQlosTUFBTSxDQUFDSyxJQUFQLENBQVksTUFBWixFQUFvQkssR0FBcEI7QUFDckIsS0FIRCxNQUdPO0FBQ0xWLE1BQUFBLE1BQU0sQ0FBQ0ssSUFBUCxDQUFZLE1BQVosRUFBb0JJLEdBQXBCO0FBQ0Q7QUFDRixHQVBEO0FBU0FiLEVBQUFBLEtBQUssQ0FBQ00sRUFBTixDQUFTLEtBQVQsRUFBZ0IsWUFBTTtBQUNwQkYsSUFBQUEsTUFBTSxDQUFDSyxJQUFQLENBQVksS0FBWjtBQUNELEdBRkQsRUFwQzRCLENBd0M1Qjs7QUFDQSxNQUFNUSxHQUFHLEdBQUdmLEdBQUcsQ0FBQ0ksRUFBaEI7O0FBQ0FKLEVBQUFBLEdBQUcsQ0FBQ0ksRUFBSixHQUFTLFVBQVNNLElBQVQsRUFBZU0sRUFBZixFQUFtQjtBQUMxQixRQUFJTixJQUFJLEtBQUssTUFBVCxJQUFtQkEsSUFBSSxLQUFLLEtBQWhDLEVBQXVDO0FBQ3JDUixNQUFBQSxNQUFNLENBQUNFLEVBQVAsQ0FBVU0sSUFBVixFQUFnQk0sRUFBRSxDQUFDQyxJQUFILENBQVFqQixHQUFSLENBQWhCO0FBQ0QsS0FGRCxNQUVPLElBQUlVLElBQUksS0FBSyxPQUFiLEVBQXNCO0FBQzNCUixNQUFBQSxNQUFNLENBQUNFLEVBQVAsQ0FBVU0sSUFBVixFQUFnQk0sRUFBRSxDQUFDQyxJQUFILENBQVFqQixHQUFSLENBQWhCOztBQUNBZSxNQUFBQSxHQUFHLENBQUNHLElBQUosQ0FBU2xCLEdBQVQsRUFBY1UsSUFBZCxFQUFvQk0sRUFBcEI7QUFDRCxLQUhNLE1BR0E7QUFDTEQsTUFBQUEsR0FBRyxDQUFDRyxJQUFKLENBQVNsQixHQUFULEVBQWNVLElBQWQsRUFBb0JNLEVBQXBCO0FBQ0Q7O0FBRUQsV0FBTyxJQUFQO0FBQ0QsR0FYRDtBQVlELENBdEREIiwic291cmNlc0NvbnRlbnQiOlsiLyoqXG4gKiBNb2R1bGUgZGVwZW5kZW5jaWVzLlxuICovXG5cbmNvbnN0IHsgU3RyaW5nRGVjb2RlciB9ID0gcmVxdWlyZSgnc3RyaW5nX2RlY29kZXInKTtcbmNvbnN0IFN0cmVhbSA9IHJlcXVpcmUoJ3N0cmVhbScpO1xuY29uc3QgemxpYiA9IHJlcXVpcmUoJ3psaWInKTtcblxuLyoqXG4gKiBCdWZmZXJzIHJlc3BvbnNlIGRhdGEgZXZlbnRzIGFuZCByZS1lbWl0cyB3aGVuIHRoZXkncmUgdW56aXBwZWQuXG4gKlxuICogQHBhcmFtIHtSZXF1ZXN0fSByZXFcbiAqIEBwYXJhbSB7UmVzcG9uc2V9IHJlc1xuICogQGFwaSBwcml2YXRlXG4gKi9cblxuZXhwb3J0cy51bnppcCA9IChyZXEsIHJlcykgPT4ge1xuICBjb25zdCB1bnppcCA9IHpsaWIuY3JlYXRlVW56aXAoKTtcbiAgY29uc3Qgc3RyZWFtID0gbmV3IFN0cmVhbSgpO1xuICBsZXQgZGVjb2RlcjtcblxuICAvLyBtYWtlIG5vZGUgcmVzcG9uc2VPbkVuZCgpIGhhcHB5XG4gIHN0cmVhbS5yZXEgPSByZXE7XG5cbiAgdW56aXAub24oJ2Vycm9yJywgZXJyID0+IHtcbiAgICBpZiAoZXJyICYmIGVyci5jb2RlID09PSAnWl9CVUZfRVJST1InKSB7XG4gICAgICAvLyB1bmV4cGVjdGVkIGVuZCBvZiBmaWxlIGlzIGlnbm9yZWQgYnkgYnJvd3NlcnMgYW5kIGN1cmxcbiAgICAgIHN0cmVhbS5lbWl0KCdlbmQnKTtcbiAgICAgIHJldHVybjtcbiAgICB9XG5cbiAgICBzdHJlYW0uZW1pdCgnZXJyb3InLCBlcnIpO1xuICB9KTtcblxuICAvLyBwaXBlIHRvIHVuemlwXG4gIHJlcy5waXBlKHVuemlwKTtcblxuICAvLyBvdmVycmlkZSBgc2V0RW5jb2RpbmdgIHRvIGNhcHR1cmUgZW5jb2RpbmdcbiAgcmVzLnNldEVuY29kaW5nID0gdHlwZSA9PiB7XG4gICAgZGVjb2RlciA9IG5ldyBTdHJpbmdEZWNvZGVyKHR5cGUpO1xuICB9O1xuXG4gIC8vIGRlY29kZSB1cG9uIGRlY29tcHJlc3Npbmcgd2l0aCBjYXB0dXJlZCBlbmNvZGluZ1xuICB1bnppcC5vbignZGF0YScsIGJ1ZiA9PiB7XG4gICAgaWYgKGRlY29kZXIpIHtcbiAgICAgIGNvbnN0IHN0ciA9IGRlY29kZXIud3JpdGUoYnVmKTtcbiAgICAgIGlmIChzdHIubGVuZ3RoID4gMCkgc3RyZWFtLmVtaXQoJ2RhdGEnLCBzdHIpO1xuICAgIH0gZWxzZSB7XG4gICAgICBzdHJlYW0uZW1pdCgnZGF0YScsIGJ1Zik7XG4gICAgfVxuICB9KTtcblxuICB1bnppcC5vbignZW5kJywgKCkgPT4ge1xuICAgIHN0cmVhbS5lbWl0KCdlbmQnKTtcbiAgfSk7XG5cbiAgLy8gb3ZlcnJpZGUgYG9uYCB0byBjYXB0dXJlIGRhdGEgbGlzdGVuZXJzXG4gIGNvbnN0IF9vbiA9IHJlcy5vbjtcbiAgcmVzLm9uID0gZnVuY3Rpb24odHlwZSwgZm4pIHtcbiAgICBpZiAodHlwZSA9PT0gJ2RhdGEnIHx8IHR5cGUgPT09ICdlbmQnKSB7XG4gICAgICBzdHJlYW0ub24odHlwZSwgZm4uYmluZChyZXMpKTtcbiAgICB9IGVsc2UgaWYgKHR5cGUgPT09ICdlcnJvcicpIHtcbiAgICAgIHN0cmVhbS5vbih0eXBlLCBmbi5iaW5kKHJlcykpO1xuICAgICAgX29uLmNhbGwocmVzLCB0eXBlLCBmbik7XG4gICAgfSBlbHNlIHtcbiAgICAgIF9vbi5jYWxsKHJlcywgdHlwZSwgZm4pO1xuICAgIH1cblxuICAgIHJldHVybiB0aGlzO1xuICB9O1xufTtcbiJdfQ==
}, function(modId) { var map = {}; return __REQUIRE__(map[modId], modId); })
__DEFINE__(1603008214471, function(require, module, exports) {


/**
 * Module dependencies.
 */
var util = require('util');

var Stream = require('stream');

var ResponseBase = require('../response-base');
/**
 * Expose `Response`.
 */


module.exports = Response;
/**
 * Initialize a new `Response` with the given `xhr`.
 *
 *  - set flags (.ok, .error, etc)
 *  - parse header
 *
 * @param {Request} req
 * @param {Object} options
 * @constructor
 * @extends {Stream}
 * @implements {ReadableStream}
 * @api private
 */

function Response(req) {
  Stream.call(this);
  this.res = req.res;
  var res = this.res;
  this.request = req;
  this.req = req.req;
  this.text = res.text;
  this.body = res.body === undefined ? {} : res.body;
  this.files = res.files || {};
  this.buffered = req._resBuffered;
  this.headers = res.headers;
  this.header = this.headers;

  this._setStatusProperties(res.statusCode);

  this._setHeaderProperties(this.header);

  this.setEncoding = res.setEncoding.bind(res);
  res.on('data', this.emit.bind(this, 'data'));
  res.on('end', this.emit.bind(this, 'end'));
  res.on('close', this.emit.bind(this, 'close'));
  res.on('error', this.emit.bind(this, 'error'));
}
/**
 * Inherit from `Stream`.
 */


util.inherits(Response, Stream); // eslint-disable-next-line new-cap

ResponseBase(Response.prototype);
/**
 * Implements methods of a `ReadableStream`
 */

Response.prototype.destroy = function (err) {
  this.res.destroy(err);
};
/**
 * Pause.
 */


Response.prototype.pause = function () {
  this.res.pause();
};
/**
 * Resume.
 */


Response.prototype.resume = function () {
  this.res.resume();
};
/**
 * Return an `Error` representative of this response.
 *
 * @return {Error}
 * @api public
 */


Response.prototype.toError = function () {
  var req = this.req;
  var method = req.method;
  var path = req.path;
  var msg = "cannot ".concat(method, " ").concat(path, " (").concat(this.status, ")");
  var err = new Error(msg);
  err.status = this.status;
  err.text = this.text;
  err.method = method;
  err.path = path;
  return err;
};

Response.prototype.setStatusProperties = function (status) {
  console.warn('In superagent 2.x setStatusProperties is a private method');
  return this._setStatusProperties(status);
};
/**
 * To json.
 *
 * @return {Object}
 * @api public
 */


Response.prototype.toJSON = function () {
  return {
    req: this.request.toJSON(),
    header: this.header,
    status: this.status,
    text: this.text
  };
};
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbIi4uLy4uL3NyYy9ub2RlL3Jlc3BvbnNlLmpzIl0sIm5hbWVzIjpbInV0aWwiLCJyZXF1aXJlIiwiU3RyZWFtIiwiUmVzcG9uc2VCYXNlIiwibW9kdWxlIiwiZXhwb3J0cyIsIlJlc3BvbnNlIiwicmVxIiwiY2FsbCIsInJlcyIsInJlcXVlc3QiLCJ0ZXh0IiwiYm9keSIsInVuZGVmaW5lZCIsImZpbGVzIiwiYnVmZmVyZWQiLCJfcmVzQnVmZmVyZWQiLCJoZWFkZXJzIiwiaGVhZGVyIiwiX3NldFN0YXR1c1Byb3BlcnRpZXMiLCJzdGF0dXNDb2RlIiwiX3NldEhlYWRlclByb3BlcnRpZXMiLCJzZXRFbmNvZGluZyIsImJpbmQiLCJvbiIsImVtaXQiLCJpbmhlcml0cyIsInByb3RvdHlwZSIsImRlc3Ryb3kiLCJlcnIiLCJwYXVzZSIsInJlc3VtZSIsInRvRXJyb3IiLCJtZXRob2QiLCJwYXRoIiwibXNnIiwic3RhdHVzIiwiRXJyb3IiLCJzZXRTdGF0dXNQcm9wZXJ0aWVzIiwiY29uc29sZSIsIndhcm4iLCJ0b0pTT04iXSwibWFwcGluZ3MiOiI7O0FBQUE7OztBQUlBLElBQU1BLElBQUksR0FBR0MsT0FBTyxDQUFDLE1BQUQsQ0FBcEI7O0FBQ0EsSUFBTUMsTUFBTSxHQUFHRCxPQUFPLENBQUMsUUFBRCxDQUF0Qjs7QUFDQSxJQUFNRSxZQUFZLEdBQUdGLE9BQU8sQ0FBQyxrQkFBRCxDQUE1QjtBQUVBOzs7OztBQUlBRyxNQUFNLENBQUNDLE9BQVAsR0FBaUJDLFFBQWpCO0FBRUE7Ozs7Ozs7Ozs7Ozs7O0FBY0EsU0FBU0EsUUFBVCxDQUFrQkMsR0FBbEIsRUFBdUI7QUFDckJMLEVBQUFBLE1BQU0sQ0FBQ00sSUFBUCxDQUFZLElBQVo7QUFDQSxPQUFLQyxHQUFMLEdBQVdGLEdBQUcsQ0FBQ0UsR0FBZjtBQUZxQixNQUdiQSxHQUhhLEdBR0wsSUFISyxDQUdiQSxHQUhhO0FBSXJCLE9BQUtDLE9BQUwsR0FBZUgsR0FBZjtBQUNBLE9BQUtBLEdBQUwsR0FB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LFVBQVNGLE1BQVQsRUFBaUI7QUFDeERHLEVBQUFBLE9BQU8sQ0FBQ0MsSUFBUixDQUFhLDJEQUFiO0FBQ0EsU0FBTyxLQUFLckIsb0JBQUwsQ0FBMEJpQixNQUExQixDQUFQO0FBQ0QsQ0FIRDtBQUtBOzs7Ozs7OztBQU9BOUIsUUFBUSxDQUFDcUIsU0FBVCxDQUFtQmMsTUFBbkIsR0FBNEIsWUFBVztBQUNyQyxTQUFPO0FBQ0xsQyxJQUFBQSxHQUFHLEVBQUUsS0FBS0csT0FBTCxDQUFhK0IsTUFBYixFQURBO0FBRUx2QixJQUFBQSxNQUFNLEVBQUUsS0FBS0EsTUFGUjtBQUdMa0IsSUFBQUEsTUFBTSxFQUFFLEtBQUtBLE1BSFI7QUFJTHpCLElBQUFBLElBQUksRUFBRSxLQUFLQTtBQUpOLEdBQVA7QUFNRCxDQVBEIiwic291cmNlc0NvbnRlbnQiOlsiLyoqXG4gKiBNb2R1bGUgZGVwZW5kZW5jaWVzLlxuICovXG5cbmNvbnN0IHV0aWwgPSByZXF1aXJlKCd1dGlsJyk7XG5jb25zdCBTdHJlYW0gPSByZXF1aXJlKCdzdHJlYW0nKTtcbmNvbnN0IFJlc3BvbnNlQmFzZSA9IHJlcXVpcmUoJy4uL3Jlc3BvbnNlLWJhc2UnKTtcblxuLyoqXG4gKiBFeHBvc2UgYFJlc3BvbnNlYC5cbiAqL1xuXG5tb2R1bGUuZXhwb3J0cyA9IFJlc3BvbnNlO1xuXG4vKipcbiAqIEluaXRpYWxpemUgYSBuZXcgYFJlc3BvbnNlYCB3aXRoIHRoZSBnaXZlbiBgeGhyYC5cbiAqXG4gKiAgLSBzZXQgZmxhZ3MgKC5vaywgLmVycm9yLCBldGMpXG4gKiAgLSBwYXJzZSBoZWFkZXJcbiAqXG4gKiBAcGFyYW0ge1JlcXVlc3R9IHJlcVxuICogQHBhcmFtIHtPYmplY3R9IG9wdGlvbnNcbiAqIEBjb25zdHJ1Y3RvclxuICogQGV4dGVuZHMge1N0cmVhbX1cbiAqIEBpbXBsZW1lbnRzIHtSZWFkYWJsZVN0cmVhbX1cbiAqIEBhcGkgcHJpdmF0ZVxuICovXG5cbmZ1bmN0aW9uIFJlc3BvbnNlKHJlcSkge1xuICBTdHJlYW0uY2FsbCh0aGlzKTtcbiAgdGhpcy5yZXMgPSByZXEucmVzO1xuICBjb25zdCB7IHJlcyB9ID0gdGhpcztcbiAgdGhpcy5yZXF1ZXN0ID0gcmVxO1xuICB0aGlzLnJlcSA9IHJlcS5yZXE7XG4gIHRoaXMudGV4dCA9IHJlcy50ZXh0O1xuICB0aGlzLmJvZHkgPSByZXMuYm9keSA9PT0gdW5kZWZpbmVkID8ge30gOiByZXMuYm9keTtcbiAgdGhpcy5maWxlcyA9IHJlcy5maWxlcyB8fCB7fTtcbiAgdGhpcy5idWZmZXJlZCA9IHJlcS5fcmVzQnVmZmVyZWQ7XG4gIHRoaXMuaGVhZGVycyA9IHJlcy5oZWFkZXJzO1xuICB0aGlzLmhlYWRlciA9IHRoaXMuaGVhZGVycztcbiAgdGhpcy5fc2V0U3RhdHVzUHJvcGVydGllcyhyZXMuc3RhdHVzQ29kZSk7XG4gIHRoaXMuX3NldEhlYWRlclByb3BlcnRpZXModGhpcy5oZWFkZXIpO1xuICB0aGlzLnNldEVuY29kaW5nID0gcmVzLnNldEVuY29kaW5nLmJpbmQocmVzKTtcbiAgcmVzLm9uKCdkYXRhJywgdGhpcy5lbWl0LmJpbmQodGhpcywgJ2RhdGEnKSk7XG4gIHJlcy5vbignZW5kJywgdGhpcy5lbWl0LmJpbmQodGhpcywgJ2VuZCcpKTtcbiAgcmVzLm9uKCdjbG9zZScsIHRoaXMuZW1pdC5iaW5kKHRoaXMsICdjbG9zZScpKTtcbiAgcmVzLm9uKCdlcnJvcicsIHRoaXMuZW1pdC5iaW5kKHRoaXMsICdlcnJvcicpKTtcbn1cblxuLyoqXG4gKiBJbmhlcml0IGZyb20gYFN0cmVhbWAuXG4gKi9cblxudXRpbC5pbmhlcml0cyhSZXNwb25zZSwgU3RyZWFtKTtcbi8vIGVzbGludC1kaXNhYmxlLW5leHQtbGluZSBuZXctY2FwXG5SZXNwb25zZUJhc2UoUmVzcG9uc2UucHJvdG90eXBlKTtcblxuLyoqXG4gKiBJbXBsZW1lbnRzIG1ldGhvZHMgb2YgYSBgUmVhZGFibGVTdHJlYW1gXG4gKi9cblxuUmVzcG9uc2UucHJvdG90eXBlLmRlc3Ryb3kgPSBmdW5jdGlvbihlcnIpIHtcbiAgdGhpcy5yZXMuZGVzdHJveShlcnIpO1xufTtcblxuLyoqXG4gKiBQYXVzZS5cbiAqL1xuXG5SZXNwb25zZS5wcm90b3R5cGUucGF1c2UgPSBmdW5jdGlvbigpIHtcbiAgdGhpcy5yZXMucGF1c2UoKTtcbn07XG5cbi8qKlxuICogUmVzdW1lLlxuICovXG5cblJlc3BvbnNlLnByb3RvdHlwZS5yZXN1bWUgPSBmdW5jdGlvbigpIHtcbiAgdGhpcy5yZXMucmVzdW1lKCk7XG59O1xuXG4vKipcbiAqIFJldHVybiBhbiBgRXJyb3JgIHJlcHJlc2VudGF0aXZlIG9mIHRoaXMgcmVzcG9uc2UuXG4gKlxuICogQHJldHVybiB7RXJyb3J9XG4gKiBAYXBpIHB1YmxpY1xuICovXG5cblJlc3BvbnNlLnByb3RvdHlwZS50b0Vycm9yID0gZnVuY3Rpb24oKSB7XG4gIGNvbnN0IHsgcmVxIH0gPSB0aGlzO1xuICBjb25zdCB7IG1ldGhvZCB9ID0gcmVxO1xuICBjb25zdCB7IHBhdGggfSA9IHJlcTtcblxuICBjb25zdCBtc2cgPSBgY2Fubm90ICR7bWV0aG9kfSAke3BhdGh9ICgke3RoaXMuc3RhdHVzfSlgO1xuICBjb25zdCBlcnIgPSBuZXcgRXJyb3IobXNnKTtcbiAgZXJyLnN0YXR1cyA9IHRoaXMuc3RhdHVzO1xuICBlcnIudGV4dCA9IHRoaXMudGV4dDtcbiAgZXJyLm1ldGhvZCA9IG1ldGhvZDtcbiAgZXJyLnBhdGggPSBwYXRoO1xuXG4gIHJldHVybiBlcnI7XG59O1xuXG5SZXNwb25zZS5wcm90b3R5cGUuc2V0U3RhdHVzUHJvcGVydGllcyA9IGZ1bmN0aW9uKHN0YXR1cykge1xuICBjb25zb2xlLndhcm4oJ0luIHN1cGVyYWdlbnQgMi54IHNldFN0YXR1c1Byb3BlcnRpZXMgaXMgYSBwcml2YXRlIG1ldGhvZCcpO1xuICByZXR1cm4gdGhpcy5fc2V0U3RhdHVzUHJvcGVydGllcyhzdGF0dXMpO1xufTtcblxuLyoqXG4gKiBUbyBqc29uLlxuICpcbiAqIEByZXR1cm4ge09iamVjdH1cbiAqIEBhcGkgcHVibGljXG4gKi9cblxuUmVzcG9uc2UucHJvdG90eXBlLnRvSlNPTiA9IGZ1bmN0aW9uKCkge1xuICByZXR1cm4ge1xuICAgIHJlcTogdGhpcy5yZXF1ZXN0LnRvSlNPTigpLFxuICAgIGhlYWRlcjogdGhpcy5oZWFkZXIsXG4gICAgc3RhdHVzOiB0aGlzLnN0YXR1cyxcbiAgICB0ZXh0OiB0aGlzLnRleHRcbiAgfTtcbn07XG4iXX0=
}, function(modId) { var map = {"../response-base":1603008214472}; return __REQUIRE__(map[modId], modId); })
__DEFINE__(1603008214472, function(require, module, exports) {


/**
 * Module dependencies.
 */
var utils = require('./utils');
/**
 * Expose `ResponseBase`.
 */


module.exports = ResponseBase;
/**
 * Initialize a new `ResponseBase`.
 *
 * @api public
 */

function ResponseBase(obj) {
  if (obj) return mixin(obj);
}
/**
 * Mixin the prototype properties.
 *
 * @param {Object} obj
 * @return {Object}
 * @api private
 */


function mixin(obj) {
  for (var key in ResponseBase.prototype) {
    if (Object.prototype.hasOwnProperty.call(ResponseBase.prototype, key)) obj[key] = ResponseBase.prototype[key];
  }

  return obj;
}
/**
 * Get case-insensitive `field` value.
 *
 * @param {String} field
 * @return {String}
 * @api public
 */


ResponseBase.prototype.get = function (field) {
  return this.header[field.toLowerCase()];
};
/**
 * Set header related properties:
 *
 *   - `.type` the content type without params
 *
 * A response of "Content-Type: text/plain; charset=utf-8"
 * will provide you with a `.type` of "text/plain".
 *
 * @param {Object} header
 * @api private
 */


ResponseBase.prototype._setHeaderProperties = function (header) {
  // TODO: moar!
  // TODO: make this a util
  // content-type
  var ct = header['content-type'] || '';
  this.type = utils.type(ct); // params

  var params = utils.params(ct);

  for (var key in params) {
    if (Object.prototype.hasOwnProperty.call(params, key)) this[key] = params[key];
  }

  this.links = {}; // links

  try {
    if (header.link) {
      this.links = utils.parseLinks(header.link);
    }
  } catch (_unused) {// ignore
  }
};
/**
 * Set flags such as `.ok` based on `status`.
 *
 * For example a 2xx response will give you a `.ok` of __true__
 * whereas 5xx will be __false__ and `.error` will be __true__. The
 * `.clientError` and `.serverError` are also available to be more
 * specific, and `.statusType` is the class of error ranging from 1..5
 * sometimes useful for mapping respond colors etc.
 *
 * "sugar" properties are also defined for common cases. Currently providing:
 *
 *   - .noContent
 *   - .badRequest
 *   - .unauthorized
 *   - .notAcceptable
 *   - .notFound
 *
 * @param {Number} status
 * @api private
 */


ResponseBase.prototype._setStatusProperties = function (status) {
  var type = status / 100 | 0; // status / class

  this.statusCode = status;
  this.status = this.statusCode;
  this.statusType = type; // basics

  this.info = type === 1;
  this.ok = type === 2;
  this.redirect = type === 3;
  this.clientError = type === 4;
  this.serverError = type === 5;
  this.error = type === 4 || type === 5 ? this.toError() : false; // sugar

  this.created = status === 201;
  this.accepted = status === 202;
  this.noContent = status === 204;
  this.badRequest = status === 400;
  this.unauthorized = status === 401;
  this.notAcceptable = status === 406;
  this.forbidden = status === 403;
  this.notFound = status === 404;
  this.unprocessableEntity = status === 422;
};
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbIi4uL3NyYy9yZXNwb25zZS1iYXNlLmpzIl0sIm5hbWVzIjpbInV0aWxzIiwicmVxdWlyZSIsIm1vZHVsZSIsImV4cG9ydHMiLCJSZXNwb25zZUJhc2UiLCJvYmoiLCJtaXhpbiIsImtleSIsInByb3RvdHlwZSIsIk9iamVjdCIsImhhc093blByb3BlcnR5IiwiY2FsbCIsImdldCIsImZpZWxkIiwiaGVhZGVyIiwidG9Mb3dlckNhc2UiLCJfc2V0SGVhZGVyUHJvcGVydGllcyIsImN0IiwidHlwZSIsInBhcmFtcyIsImxpbmtzIiwibGluayIsInBhcnNlTGlua3MiLCJfc2V0U3RhdHVzUHJvcGVydGllcyIsInN0YXR1cyIsInN0YXR1c0NvZGUiLCJzdGF0dXNUeXBlIiwiaW5mbyIsIm9rIiwicmVkaXJlY3QiLCJjbGllbnRFcnJvciIsInNlcnZlckVycm9yIiwiZXJyb3IiLCJ0b0Vycm9yIiwiY3JlYXRlZCIsImFjY2VwdGVkIiwibm9Db250ZW50IiwiYmFkUmVxdWVzdCIsInVuYXV0aG9yaXplZCIsIm5vdEFjY2VwdGFibGUiLCJmb3JiaWRkZW4iLCJub3RGb3VuZCIsInVucHJvY2Vzc2FibGVFbnRpdHkiXSwibWFwcGluZ3MiOiI7O0FBQUE7OztBQUlBLElBQU1BLEtBQUssR0FBR0MsT0FBTyxDQUFDLFNBQUQsQ0FBckI7QUFFQTs7Ozs7QUFJQUMsTUFBTSxDQUFDQyxPQUFQLEdBQWlCQyxZQUFqQjtBQUVBOzs7Ozs7QUFNQSxTQUFTQSxZQUFULENBQXNCQyxHQUF0QixFQUEyQjtBQUN6QixNQUFJQSxHQUFKLEVBQVMsT0FBT0MsS0FBSyxDQUFDRCxHQUFELENBQVo7QUFDVjtBQUVEOzs7Ozs7Ozs7QUFRQSxTQUFTQyxLQUFULENBQWVELEdBQWYsRUFBb0I7QUFDbEIsT0FBSyxJQUFNRSxHQUFYLElBQWtCSCxZQUFZLENBQUNJLFNBQS9CLEVBQTBDO0FBQ3hDLFFBQUlDLE1BQU0sQ0FBQ0QsU0FBUCxDQUFpQkUsY0FBakIsQ0FBZ0NDLElBQWhDLENBQXFDUCxZQUFZLENBQUNJLFNBQWxELEVBQTZERCxHQUE3RCxDQUFKLEVBQ0VGLEdBQUcsQ0FBQ0UsR0FBRCxDQUFILEdBQVdILFlBQVksQ0FBQ0ksU0FBYixDQUF1QkQsR0FBdkIsQ0FBWDtBQUNIOztBQUVELFNBQU9GLEdBQVA7QUFDRDtBQUVEOzs7Ozs7Ozs7QUFRQUQsWUFBWSxDQUFDSSxTQUFiLENBQXVCSSxHQUF2QixHQUE2QixVQUFTQyxLQUFULEVBQWdCO0FBQzNDLFNBQU8sS0FBS0MsTUFBTCxDQUFZRCxLQUFLLENBQUNFLFdBQU4sRUFBWixDQUFQO0FBQ0QsQ0FGRDtBQUlBOzs7Ozs7Ozs7Ozs7O0FBWUFYLFlBQVksQ0FBQ0ksU0FBYixDQUF1QlEsb0JBQXZCLEdBQThDLFVBQVNGLE1BQVQsRUFBaUI7QUFDN0Q7QUFDQTtBQUVBO0FBQ0EsTUFBTUcsRUFBRSxHQUFHSCxNQUFNLENBQUMsY0FBRCxDQUFOLElBQTBCLEVBQXJDO0FBQ0EsT0FBS0ksSUFBTCxHQUFZbEIsS0FBSyxDQUFDa0IsSUFBTixDQUFXRCxFQUFYLENBQVosQ0FONkQsQ0FRN0Q7O0FBQ0EsTUFBTUUsTUFBTSxHQUFHbkIsS0FBSyxDQUFDbUIsTUFBTixDQUFhRixFQUFiLENBQWY7O0FBQ0EsT0FBSyxJQUFNVixHQUFYLElBQWtCWSxNQUFsQixFQUEwQjtBQUN4QixRQUFJVixNQUFNLENBQUNELFNBQVAsQ0FBaUJFLGNBQWpCLENBQWdDQyxJQUFoQyxDQUFxQ1EsTUFBckMsRUFBNkNaLEdBQTdDLENBQUosRUFDRSxLQUFLQSxHQUFMLElBQVlZLE1BQU0sQ0FBQ1osR0FBRCxDQUFsQjtBQUNIOztBQUVELE9BQUthLEtBQUwsR0FBYSxFQUFiLENBZjZELENBaUI3RDs7QUFDQSxNQUFJO0FBQ0YsUUFBSU4sTUFBTSxDQUFDTyxJQUFYLEVBQWlCO0FBQ2YsV0FBS0QsS0FBTCxHQUFhcEIsS0FBSyxDQUFDc0IsVUFBTixDQUFpQlIsTUFBTSxDQUFDTyxJQUF4QixDQUFiO0FBQ0Q7QUFDRixHQUpELENBSUUsZ0JBQU0sQ0FDTjtBQUNEO0FBQ0YsQ0F6QkQ7QUEyQkE7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7QUFxQkFqQixZQUFZLENBQUNJLFNBQWIsQ0FBdUJlLG9CQUF2QixHQUE4QyxVQUFTQyxNQUFULEVBQWlCO0FBQzdELE1BQU1OLElBQUksR0FBSU0sTUFBTSxHQUFHLEdBQVYsR0FBaUIsQ0FBOUIsQ0FENkQsQ0FHN0Q7O0FBQ0EsT0FBS0MsVUFBTCxHQUFrQkQsTUFBbEI7QUFDQSxPQUFLQSxNQUFMLEdBQWMsS0FBS0MsVUFBbkI7QUFDQSxPQUFLQyxVQUFMLEdBQWtCUixJQUFsQixDQU42RCxDQVE3RDs7QUFDQSxPQUFLUyxJQUFMLEdBQVlULElBQUksS0FBSyxDQUFyQjtBQUNBLE9BQUtVLEVBQUwsR0FBVVYsSUFBSSxLQUFLLENBQW5CO0FBQ0EsT0FBS1csUUFBTCxHQUFnQlgsSUFBSSxLQUFLLENBQXpCO0FBQ0EsT0FBS1ksV0FBTCxHQUFtQlosSUFBSSxLQUFLLENBQTVCO0FBQ0EsT0FBS2EsV0FBTCxHQUFtQmIsSUFBSSxLQUFLLENBQTVCO0FBQ0EsT0FBS2MsS0FBTCxHQUFhZCxJQUFJLEtBQUssQ0FBVCxJQUFjQSxJQUFJLEtBQUssQ0FBdkIsR0FBMkIsS0FBS2UsT0FBTCxFQUEzQixHQUE0QyxLQUF6RCxDQWQ2RCxDQWdCN0Q7O0FBQ0EsT0FBS0MsT0FBTCxHQUFlVixNQUFNLEtBQUssR0FBMUI7QUFDQSxPQUFLVyxRQUFMLEdBQWdCWCxNQUFNLEtBQUssR0FBM0I7QUFDQSxPQUFLWSxTQUFMLEdBQWlCWixNQUFNLEtBQUssR0FBNUI7QUFDQSxPQUFLYSxVQUFMLEdBQWtCYixNQUFNLEtBQUssR0FBN0I7QUFDQSxPQUFLYyxZQUFMLEdBQW9CZCxNQUFNLEtBQUssR0FBL0I7QUFDQSxPQUFLZSxhQUFMLEdBQXFCZixNQUFNLEtBQUssR0FBaEM7QUFDQSxPQUFLZ0IsU0FBTCxHQUFpQmhCLE1BQU0sS0FBSyxHQUE1QjtBQUNBLE9BQUtpQixRQUFMLEdBQWdCakIsTUFBTSxLQUFLLEdBQTNCO0FBQ0EsT0FBS2tCLG1CQUFMLEdBQTJCbEIsTUFBTSxLQUFLLEdBQXRDO0FBQ0QsQ0ExQkQiLCJzb3VyY2VzQ29udGVudCI6WyIvKipcbiAqIE1vZHVsZSBkZXBlbmRlbmNpZXMuXG4gKi9cblxuY29uc3QgdXRpbHMgPSByZXF1aXJlKCcuL3V0aWxzJyk7XG5cbi8qKlxuICogRXhwb3NlIGBSZXNwb25zZUJhc2VgLlxuICovXG5cbm1vZHVsZS5leHBvcnRzID0gUmVzcG9uc2VCYXNlO1xuXG4vKipcbiAqIEluaXRpYWxpemUgYSBuZXcgYFJlc3BvbnNlQmFzZWAuXG4gKlxuICogQGFwaSBwdWJsaWNcbiAqL1xuXG5mdW5jdGlvbiBSZXNwb25zZUJhc2Uob2JqKSB7XG4gIGlmIChvYmopIHJldHVybiBtaXhpbihvYmopO1xufVxuXG4vKipcbiAqIE1peGluIHRoZSBwcm90b3R5cGUgcHJvcGVydGllcy5cbiAqXG4gKiBAcGFyYW0ge09iamVjdH0gb2JqXG4gKiBAcmV0dXJuIHtPYmplY3R9XG4gKiBAYXBpIHByaXZhdGVcbiAqL1xuXG5mdW5jdGlvbiBtaXhpbihvYmopIHtcbiAgZm9yIChjb25zdCBrZXkgaW4gUmVzcG9uc2VCYXNlLnByb3RvdHlwZSkge1xuICAgIGlmIChPYmplY3QucHJvdG90eXBlLmhhc093blByb3BlcnR5LmNhbGwoUmVzcG9uc2VCYXNlLnByb3RvdHlwZSwga2V5KSlcbiAgICAgIG9ialtrZXldID0gUmVzcG9uc2VCYXNlLnByb3RvdHlwZVtrZXldO1xuICB9XG5cbiAgcmV0dXJuIG9iajtcbn1cblxuLyoqXG4gKiBHZXQgY2FzZS1pbnNlbnNpdGl2ZSBgZmllbGRgIHZhbHVlLlxuICpcbiAqIEBwYXJhbSB7U3RyaW5nfSBmaWVsZFxuICogQHJldHVybiB7U3RyaW5nfVxuICogQGFwaSBwdWJsaWNcbiAqL1xuXG5SZXNwb25zZUJhc2UucHJvdG90eXBlLmdldCA9IGZ1bmN0aW9uKGZpZWxkKSB7XG4gIHJldHVybiB0aGlzLmhlYWRlcltmaWVsZC50b0xvd2VyQ2FzZSgpXTtcbn07XG5cbi8qKlxuICogU2V0IGhlYWRlciByZWxhdGVkIHByb3BlcnRpZXM6XG4gKlxuICogICAtIGAudHlwZWAgdGhlIGNvbnRlbnQgdHlwZSB3aXRob3V0IHBhcmFtc1xuICpcbiAqIEEgcmVzcG9uc2Ugb2YgXCJDb250ZW50LVR5cGU6IHRleHQvcGxhaW47IGNoYXJzZXQ9dXRmLThcIlxuICogd2lsbCBwcm92aWRlIHlvdSB3aXRoIGEgYC50eXBlYCBvZiBcInRleHQvcGxhaW5cIi5cbiAqXG4gKiBAcGFyYW0ge09iamVjdH0gaGVhZGVyXG4gKiBAYXBpIHByaXZhdGVcbiAqL1xuXG5SZXNwb25zZUJhc2UucHJvdG90eXBlLl9zZXRIZWFkZXJQcm9wZXJ0aWVzID0gZnVuY3Rpb24oaGVhZGVyKSB7XG4gIC8vIFRPRE86IG1vYXIhXG4gIC8vIFRPRE86IG1ha2UgdGhpcyBhIHV0aWxcblxuICAvLyBjb250ZW50LXR5cGVcbiAgY29uc3QgY3QgPSBoZWFkZXJbJ2NvbnRlbnQtdHlwZSddIHx8ICcnO1xuICB0aGlzLnR5cGUgPSB1dGlscy50eXBlKGN0KTtcblxuICAvLyBwYXJhbXNcbiAgY29uc3QgcGFyYW1zID0gdXRpbHMucGFyYW1zKGN0KTtcbiAgZm9yIChjb25zdCBrZXkgaW4gcGFyYW1zKSB7XG4gICAgaWYgKE9iamVjdC5wcm90b3R5cGUuaGFzT3duUHJvcGVydHkuY2FsbChwYXJhbXMsIGtleSkpXG4gICAgICB0aGlzW2tleV0gPSBwYXJhbXNba2V5XTtcbiAgfVxuXG4gIHRoaXMubGlua3MgPSB7fTtcblxuICAvLyBsaW5rc1xuICB0cnkge1xuICAgIGlmIChoZWFkZXIubGluaykge1xuICAgICAgdGhpcy5saW5rcyA9IHV0aWxzLnBhcnNlTGlua3MoaGVhZGVyLmxpbmspO1xuICAgIH1cbiAgfSBjYXRjaCB7XG4gICAgLy8gaWdub3JlXG4gIH1cbn07XG5cbi8qKlxuICogU2V0IGZsYWdzIHN1Y2ggYXMgYC5va2AgYmFzZWQgb24gYHN0YXR1c2AuXG4gKlxuICogRm9yIGV4YW1wbGUgYSAyeHggcmVzcG9uc2Ugd2lsbCBnaXZlIHlvdSBhIGAub2tgIG9mIF9fdHJ1ZV9fXG4gKiB3aGVyZWFzIDV4eCB3aWxsIGJlIF9fZmFsc2VfXyBhbmQgYC5lcnJvcmAgd2lsbCBiZSBfX3RydWVfXy4gVGhlXG4gKiBgLmNsaWVudEVycm9yYCBhbmQgYC5zZXJ2ZXJFcnJvcmAgYXJlIGFsc28gYXZhaWxhYmxlIHRvIGJlIG1vcmVcbiAqIHNwZWNpZmljLCBhbmQgYC5zdGF0dXNUeXBlYCBpcyB0aGUgY2xhc3Mgb2YgZXJyb3IgcmFuZ2luZyBmcm9tIDEuLjVcbiAqIHNvbWV0aW1lcyB1c2VmdWwgZm9yIG1hcHBpbmcgcmVzcG9uZCBjb2xvcnMgZXRjLlxuICpcbiAqIFwic3VnYXJcIiBwcm9wZXJ0aWVzIGFyZSBhbHNvIGRlZmluZWQgZm9yIGNvbW1vbiBjYXNlcy4gQ3VycmVudGx5IHByb3ZpZGluZzpcbiAqXG4gKiAgIC0gLm5vQ29udGVudFxuICogICAtIC5iYWRSZXF1ZXN0XG4gKiAgIC0gLnVuYXV0aG9yaXplZFxuICogICAtIC5ub3RBY2NlcHRhYmxlXG4gKiAgIC0gLm5vdEZvdW5kXG4gKlxuICogQHBhcmFtIHtOdW1iZXJ9IHN0YXR1c1xuICogQGFwaSBwcml2YXRlXG4gKi9cblxuUmVzcG9uc2VCYXNlLnByb3RvdHlwZS5fc2V0U3RhdHVzUHJvcGVydGllcyA9IGZ1bmN0aW9uKHN0YXR1cykge1xuICBjb25zdCB0eXBlID0gKHN0YXR1cyAvIDEwMCkgfCAwO1xuXG4gIC8vIHN0YXR1cyAvIGNsYXNzXG4gIHRoaXMuc3RhdHVzQ29kZSA9IHN0YXR1cztcbiAgdGhpcy5zdGF0dXMgPSB0aGlzLnN0YXR1c0NvZGU7XG4gIHRoaXMuc3RhdHVzVHlwZSA9IHR5cGU7XG5cbiAgLy8gYmFzaWNzXG4gIHRoaXMuaW5mbyA9IHR5cGUgPT09IDE7XG4gIHRoaXMub2sgPSB0eXBlID09PSAyO1xuICB0aGlzLnJlZGlyZWN0ID0gdHlwZSA9PT0gMztcbiAgdGhpcy5jbGllbnRFcnJvciA9IHR5cGUgPT09IDQ7XG4gIHRoaXMuc2VydmVyRXJyb3IgPSB0eXBlID09PSA1O1xuICB0aGlzLmVycm9yID0gdHlwZSA9PT0gNCB8fCB0eXBlID09PSA1ID8gdGhpcy50b0Vycm9yKCkgOiBmYWxzZTtcblxuICAvLyBzdWdhclxuICB0aGlzLmNyZWF0ZWQgPSBzdGF0dXMgPT09IDIwMTtcbiAgdGhpcy5hY2NlcHRlZCA9IHN0YXR1cyA9PT0gMjAyO1xuICB0aGlzLm5vQ29udGVudCA9IHN0YXR1cyA9PT0gMjA0O1xuICB0aGlzLmJhZFJlcXVlc3QgPSBzdGF0dXMgPT09IDQwMDtcbiAgdGhpcy51bmF1dGhvcml6ZWQgPSBzdGF0dXMgPT09IDQwMTtcbiAgdGhpcy5ub3RBY2NlcHRhYmxlID0gc3RhdHVzID09PSA0MDY7XG4gIHRoaXMuZm9yYmlkZGVuID0gc3RhdHVzID09PSA0MDM7XG4gIHRoaXMubm90Rm91bmQgPSBzdGF0dXMgPT09IDQwNDtcbiAgdGhpcy51bnByb2Nlc3NhYmxlRW50aXR5ID0gc3RhdHVzID09PSA0MjI7XG59O1xuIl19
}, function(modId) { var map = {"./utils":1603008214467}; return __REQUIRE__(map[modId], modId); })
__DEFINE__(1603008214473, function(require, module, exports) {


function ownKeys(object, enumerableOnly) { var keys = Object.keys(object); if (Object.getOwnPropertySymbols) { var symbols = Object.getOwnPropertySymbols(object); if (enumerableOnly) symbols = symbols.filter(function (sym) { return Object.getOwnPropertyDescriptor(object, sym).enumerable; }); keys.push.apply(keys, symbols); } return keys; }

function _objectSpread(target) { for (var i = 1; i < arguments.length; i++) { var source = arguments[i] != null ? arguments[i] : {}; if (i % 2) { ownKeys(Object(source), true).forEach(function (key) { _defineProperty(target, key, source[key]); }); } else if (Object.getOwnPropertyDescriptors) { Object.defineProperties(target, Object.getOwnPropertyDescriptors(source)); } else { ownKeys(Object(source)).forEach(function (key) { Object.defineProperty(target, key, Object.getOwnPropertyDescriptor(source, key)); }); } } return target; }

function _defineProperty(obj, key, value) { if (key in obj) { Object.defineProperty(obj, key, { value: value, enumerable: true, configurable: true, writable: true }); } else { obj[key] = value; } return obj; }

var Stream = require('stream');

var util = require('util');

var net = require('net');

var tls = require('tls'); // eslint-disable-next-line node/no-deprecated-api


var _require = require('url'),
    parse = _require.parse;

var semver = require('semver');

var http2;
if (semver.gte(process.version, 'v10.10.0')) http2 = require('http2');else throw new Error('superagent: this version of Node.js does not support http2');
var _http2$constants = http2.constants,
    HTTP2_HEADER_PATH = _http2$constants.HTTP2_HEADER_PATH,
    HTTP2_HEADER_STATUS = _http2$constants.HTTP2_HEADER_STATUS,
    HTTP2_HEADER_METHOD = _http2$constants.HTTP2_HEADER_METHOD,
    HTTP2_HEADER_AUTHORITY = _http2$constants.HTTP2_HEADER_AUTHORITY,
    HTTP2_HEADER_HOST = _http2$constants.HTTP2_HEADER_HOST,
    HTTP2_HEADER_SET_COOKIE = _http2$constants.HTTP2_HEADER_SET_COOKIE,
    NGHTTP2_CANCEL = _http2$constants.NGHTTP2_CANCEL;

function setProtocol(protocol) {
  return {
    request: function request(options) {
      return new Request(protocol, options);
    }
  };
}

function Request(protocol, options) {
  var _this = this;

  Stream.call(this);
  var defaultPort = protocol === 'https:' ? 443 : 80;
  var defaultHost = 'localhost';
  var port = options.port || defaultPort;
  var host = options.host || defaultHost;
  delete options.port;
  delete options.host;
  this.method = options.method;
  this.path = options.path;
  this.protocol = protocol;
  this.host = host;
  delete options.method;
  delete options.path;

  var sessionOptions = _objectSpread({}, options);

  if (options.socketPath) {
    sessionOptions.socketPath = options.socketPath;
    sessionOptions.createConnection = this.createUnixConnection.bind(this);
  }

  this._headers = {};
  var session = http2.connect("".concat(protocol, "//").concat(host, ":").concat(port), sessionOptions);
  this.setHeader('host', "".concat(host, ":").concat(port));
  session.on('error', function (err) {
    return _this.emit('error', err);
  });
  this.session = session;
}
/**
 * Inherit from `Stream` (which inherits from `EventEmitter`).
 */


util.inherits(Request, Stream);

Request.prototype.createUnixConnection = function (authority, options) {
  switch (this.protocol) {
    case 'http:':
      return net.connect(options.socketPath);

    case 'https:':
      options.ALPNProtocols = ['h2'];
      options.servername = this.host;
      options.allowHalfOpen = true;
      return tls.connect(options.socketPath, options);

    default:
      throw new Error('Unsupported protocol', this.protocol);
  }
}; // eslint-disable-next-line no-unused-vars


Request.prototype.setNoDelay = function (bool) {// We can not use setNoDelay with HTTP/2.
  // Node 10 limits http2session.socket methods to ones safe to use with HTTP/2.
  // See also https://nodejs.org/api/http2.html#http2_http2session_socket
};

Request.prototype.getFrame = function () {
  var _method,
      _this2 = this;

  if (this.frame) {
    return this.frame;
  }

  var method = (_method = {}, _defineProperty(_method, HTTP2_HEADER_PATH, this.path), _defineProperty(_method, HTTP2_HEADER_METHOD, this.method), _method);
  var headers = this.mapToHttp2Header(this._headers);
  headers = Object.assign(headers, method);
  var frame = this.session.request(headers); // eslint-disable-next-line no-unused-vars

  frame.once('response', function (headers, flags) {
    headers = _this2.mapToHttpHeader(headers);
    frame.headers = headers;
    frame.statusCode = headers[HTTP2_HEADER_STATUS];
    frame.status = frame.statusCode;

    _this2.emit('response', frame);
  });
  this._headerSent = true;
  frame.once('drain', function () {
    return _this2.emit('drain');
  });
  frame.on('error', function (err) {
    return _this2.emit('error', err);
  });
  frame.on('close', function () {
    return _this2.session.close();
  });
  this.frame = frame;
  return frame;
};

Request.prototype.mapToHttpHeader = function (headers) {
  var keys = Object.keys(headers);
  var http2Headers = {};

  for (var _i = 0, _keys = keys; _i < _keys.length; _i++) {
    var key = _keys[_i];
    var value = headers[key];
    key = key.toLowerCase();

    switch (key) {
      case HTTP2_HEADER_SET_COOKIE:
        value = Array.isArray(value) ? value : [value];
        break;

      default:
        break;
    }

    http2Headers[key] = value;
  }

  return http2Headers;
};

Request.prototype.mapToHttp2Header = function (headers) {
  var keys = Object.keys(headers);
  var http2Headers = {};

  for (var _i2 = 0, _keys2 = keys; _i2 < _keys2.length; _i2++) {
    var key = _keys2[_i2];
    var value = headers[key];
    key = key.toLowerCase();

    switch (key) {
      case HTTP2_HEADER_HOST:
        key = HTTP2_HEADER_AUTHORITY;
        value = /^http:\/\/|^https:\/\//.test(value) ? parse(value).host : value;
        break;

      default:
        break;
    }

    http2Headers[key] = value;
  }

  return http2Headers;
};

Request.prototype.setHeader = function (name, value) {
  this._headers[name.toLowerCase()] = value;
};

Request.prototype.getHeader = function (name) {
  return this._headers[name.toLowerCase()];
};

Request.prototype.write = function (data, encoding) {
  var frame = this.getFrame();
  return frame.write(data, encoding);
};

Request.prototype.pipe = function (stream, options) {
  var frame = this.getFrame();
  return frame.pipe(stream, options);
};

Request.prototype.end = function (data) {
  var frame = this.getFrame();
  frame.end(data);
}; // eslint-disable-next-line no-unused-vars


Request.prototype.abort = function (data) {
  var frame = this.getFrame();
  frame.close(NGHTTP2_CANCEL);
  this.session.destroy();
};

exports.setProtocol = setProtocol;
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbIi4uLy4uL3NyYy9ub2RlL2h0dHAyd3JhcHBlci5qcyJdLCJuYW1lcyI6WyJTdHJlYW0iLCJyZXF1aXJlIiwidXRpbCIsIm5ldCIsInRscyIsInBhcnNlIiwic2VtdmVyIiwiaHR0cDIiLCJndGUiLCJwcm9jZXNzIiwidmVyc2lvbiIsIkVycm9yIiwiY29uc3RhbnRzIiwiSFRUUDJfSEVBREVSX1BBVEgiLCJIVFRQMl9IRUFERVJfU1RBVFVTIiwiSFRUUDJfSEVBREVSX01FVEhPRCIsIkhUVFAyX0hFQURFUl9BVVRIT1JJVFkiLCJIVFRQMl9IRUFERVJfSE9TVCIsIkhUVFAyX0hFQURFUl9TRVRfQ09PS0lFIiwiTkdIVFRQMl9DQU5DRUwiLCJzZXRQcm90b2NvbCIsInByb3RvY29sIiwicmVxdWVzdCIsIm9wdGlvbnMiLCJSZXF1ZXN0IiwiY2FsbCIsImRlZmF1bHRQb3J0IiwiZGVmYXVsdEhvc3QiLCJwb3J0IiwiaG9zdCIsIm1ldGhvZCIsInBhdGgiLCJzZXNzaW9uT3B0aW9ucyIsInNvY2tldFBhdGgiLCJjcmVhdGVDb25uZWN0aW9uIiwiY3JlYXRlVW5peENvbm5lY3Rpb24iLCJiaW5kIiwiX2hlYWRlcnMiLCJzZXNzaW9uIiwiY29ubmVjdCIsInNldEhlYWRlciIsIm9uIiwiZXJyIiwiZW1pdCIsImluaGVyaXRzIiwicHJvdG90eXBlIiwiYXV0aG9yaXR5IiwiQUxQTlByb3RvY29scyIsInNlcnZlcm5hbWUiLCJhbGxvd0hhbGZPcGVuIiwic2V0Tm9EZWxheSIsImJvb2wiLCJnZXRGcmFtZSIsImZyYW1lIiwiaGVhZGVycyIsIm1hcFRvSHR0cDJIZWFkZXIiLCJPYmplY3QiLCJhc3NpZ24iLCJvbmNlIiwiZmxhZ3MiLCJtYXBUb0h0dHBIZWFkZXIiLCJzdGF0dXNDb2RlIiwic3RhdHVzIiwiX2hlYWRlclNlbnQiLCJjbG9zZSIsImtleXMiLCJodHRwMkhlYWRlcnMiLCJrZXkiLCJ2YWx1ZSIsInRvTG93ZXJDYXNlIiwiQXJyYXkiLCJpc0FycmF5IiwidGVzdCIsIm5hbWUiLCJnZXRIZWFkZXIiLCJ3cml0ZSIsImRhdGEiLCJlbmNvZGluZyIsInBpcGUiLCJzdHJlYW0iLCJlbmQiLCJhYm9ydCIsImRlc3Ryb3kiLCJleHBvcnRzIl0sIm1hcHBpbmdzIjoiOzs7Ozs7OztBQUFBLElBQU1BLE1BQU0sR0FBR0MsT0FBTyxDQUFDLFFBQUQsQ0FBdEI7O0FBQ0EsSUFBTUMsSUFBSSxHQUFHRCxPQUFPLENBQUMsTUFBRCxDQUFwQjs7QUFDQSxJQUFNRSxHQUFHLEdBQUdGLE9BQU8sQ0FBQyxLQUFELENBQW5COztBQUNBLElBQU1HLEdBQUcsR0FBR0gsT0FBTyxDQUFDLEtBQUQsQ0FBbkIsQyxDQUNBOzs7ZUFDa0JBLE9BQU8sQ0FBQyxLQUFELEM7SUFBakJJLEssWUFBQUEsSzs7QUFDUixJQUFNQyxNQUFNLEdBQUdMLE9BQU8sQ0FBQyxRQUFELENBQXRCOztBQUVBLElBQUlNLEtBQUo7QUFDQSxJQUFJRCxNQUFNLENBQUNFLEdBQVAsQ0FBV0MsT0FBTyxDQUFDQyxPQUFuQixFQUE0QixVQUE1QixDQUFKLEVBQTZDSCxLQUFLLEdBQUdOLE9BQU8sQ0FBQyxPQUFELENBQWYsQ0FBN0MsS0FFRSxNQUFNLElBQUlVLEtBQUosQ0FBVSw0REFBVixDQUFOO3VCQVVFSixLQUFLLENBQUNLLFM7SUFQUkMsaUIsb0JBQUFBLGlCO0lBQ0FDLG1CLG9CQUFBQSxtQjtJQUNBQyxtQixvQkFBQUEsbUI7SUFDQUMsc0Isb0JBQUFBLHNCO0lBQ0FDLGlCLG9CQUFBQSxpQjtJQUNBQyx1QixvQkFBQUEsdUI7SUFDQUMsYyxvQkFBQUEsYzs7QUFHRixTQUFTQyxXQUFULENBQXFCQyxRQUFyQixFQUErQjtBQUM3QixTQUFPO0FBQ0xDLElBQUFBLE9BREssbUJBQ0dDLE9BREgsRUFDWTtBQUNmLGFBQU8sSUFBSUMsT0FBSixDQUFZSCxRQUFaLEVBQXNCRSxPQUF0QixDQUFQO0FBQ0Q7QUFISSxHQUFQO0FBS0Q7O0FBRUQsU0FBU0MsT0FBVCxDQUFpQkgsUUFBakIsRUFBMkJFLE9BQTNC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U0FBUixDQUFrQm1DLEdBQWxCLEdBQXdCLFVBQVNKLElBQVQsRUFBZTtBQUNyQyxNQUFNdkIsS0FBSyxHQUFHLEtBQUtELFFBQUwsRUFBZDtBQUNBQyxFQUFBQSxLQUFLLENBQUMyQixHQUFOLENBQVVKLElBQVY7QUFDRCxDQUhELEMsQ0FLQTs7O0FBQ0FwRCxPQUFPLENBQUNxQixTQUFSLENBQWtCb0MsS0FBbEIsR0FBMEIsVUFBU0wsSUFBVCxFQUFlO0FBQ3ZDLE1BQU12QixLQUFLLEdBQUcsS0FBS0QsUUFBTCxFQUFkO0FBQ0FDLEVBQUFBLEtBQUssQ0FBQ1csS0FBTixDQUFZN0MsY0FBWjtBQUNBLE9BQUttQixPQUFMLENBQWE0QyxPQUFiO0FBQ0QsQ0FKRDs7QUFNQUMsT0FBTyxDQUFDL0QsV0FBUixHQUFzQkEsV0FBdEIiLCJzb3VyY2VzQ29udGVudCI6WyJjb25zdCBTdHJlYW0gPSByZXF1aXJlKCdzdHJlYW0nKTtcbmNvbnN0IHV0aWwgPSByZXF1aXJlKCd1dGlsJyk7XG5jb25zdCBuZXQgPSByZXF1aXJlKCduZXQnKTtcbmNvbnN0IHRscyA9IHJlcXVpcmUoJ3RscycpO1xuLy8gZXNsaW50LWRpc2FibGUtbmV4dC1saW5lIG5vZGUvbm8tZGVwcmVjYXRlZC1hcGlcbmNvbnN0IHsgcGFyc2UgfSA9IHJlcXVpcmUoJ3VybCcpO1xuY29uc3Qgc2VtdmVyID0gcmVxdWlyZSgnc2VtdmVyJyk7XG5cbmxldCBodHRwMjtcbmlmIChzZW12ZXIuZ3RlKHByb2Nlc3MudmVyc2lvbiwgJ3YxMC4xMC4wJykpIGh0dHAyID0gcmVxdWlyZSgnaHR0cDInKTtcbmVsc2VcbiAgdGhyb3cgbmV3IEVycm9yKCdzdXBlcmFnZW50OiB0aGlzIHZlcnNpb24gb2YgTm9kZS5qcyBkb2VzIG5vdCBzdXBwb3J0IGh0dHAyJyk7XG5cbmNvbnN0IHtcbiAgSFRUUDJfSEVBREVSX1BBVEgsXG4gIEhUVFAyX0hFQURFUl9TVEFUVVMsXG4gIEhUVFAyX0hFQURFUl9NRVRIT0QsXG4gIEhUVFAyX0hFQURFUl9BVVRIT1JJVFksXG4gIEhUVFAyX0hFQURFUl9IT1NULFxuICBIVFRQMl9IRUFERVJfU0VUX0NPT0tJRSxcbiAgTkdIVFRQMl9DQU5DRUxcbn0gPSBodHRwMi5jb25zdGFudHM7XG5cbmZ1bmN0aW9uIHNldFByb3RvY29sKHByb3RvY29sKSB7XG4gIHJldHVybiB7XG4gICAgcmVxdWVzdChvcHRpb25zKSB7XG4gICAgICByZXR1cm4gbmV3IFJlcXVlc3QocHJvdG9jb2wsIG9wdGlvbnMpO1xuICAgIH1cbiAgfTtcbn1cblxuZnVuY3Rpb24gUmVxdWVzdChwcm90b2NvbCwgb3B0aW9ucykge1xuICBTdHJlYW0uY2FsbCh0aGlzKTtcbiAgY29uc3QgZGVmYXVsdFBvcnQgPSBwcm90b2NvbCA9PT0gJ2h0dHBzOicgPyA0NDMgOiA4MDtcbiAgY29uc3QgZGVmYXVsdEhvc3QgPSAnbG9jYWxob3N0JztcbiAgY29uc3QgcG9ydCA9IG9wdGlvbnMucG9ydCB8fCBkZWZhdWx0UG9ydDtcbiAgY29uc3QgaG9zdCA9IG9wdGlvbnMuaG9zdCB8fCBkZWZhdWx0SG9zdDtcblxuICBkZWxldGUgb3B0aW9ucy5wb3J0O1xuICBkZWxldGUgb3B0aW9ucy5ob3N0O1xuXG4gIHRoaXMubWV0aG9kID0gb3B0aW9ucy5tZXRob2Q7XG4gIHRoaXMucGF0aCA9IG9wdGlvbnMucGF0aDtcbiAgdGhpcy5wcm90b2NvbCA9IHByb3RvY29sO1xuICB0aGlzLmhvc3QgPSBob3N0O1xuXG4gIGRlbGV0ZSBvcHRpb25zLm1ldGhvZDtcbiAgZGVsZXRlIG9wdGlvbnMucGF0aDtcblxuICBjb25zdCBzZXNzaW9uT3B0aW9ucyA9IHsgLi4ub3B0aW9ucyB9O1xuICBpZiAob3B0aW9ucy5zb2NrZXRQYXRoKSB7XG4gICAgc2Vzc2lvbk9wdGlvbnMuc29ja2V0UGF0aCA9IG9wdGlvbnMuc29ja2V0UGF0aDtcbiAgICBzZXNzaW9uT3B0aW9ucy5jcmVhdGVDb25uZWN0aW9uID0gdGhpcy5jcmVhdGVVbml4Q29ubmVjdGlvbi5iaW5kKHRoaXMpO1xuICB9XG5cbiAgdGhpcy5faGVhZGVycyA9IHt9O1xuXG4gIGNvbnN0IHNlc3Npb24gPSBodHRwMi5jb25uZWN0KGAke3Byb3RvY29sfS8vJHtob3N0fToke3BvcnR9YCwgc2Vzc2lvbk9wdGlvbnMpO1xuICB0aGlzLnNldEhlYWRlcignaG9zdCcsIGAke2hvc3R9OiR7cG9ydH1gKTtcblxuICBzZXNzaW9uLm9uKCdlcnJvcicsIGVyciA9PiB0aGlzLmVtaXQoJ2Vycm9yJywgZXJyKSk7XG5cbiAgdGhpcy5zZXNzaW9uID0gc2Vzc2lvbjtcbn1cblxuLyoqXG4gKiBJbmhlcml0IGZyb20gYFN0cmVhbWAgKHdoaWNoIGluaGVyaXRzIGZyb20gYEV2ZW50RW1pdHRlcmApLlxuICovXG51dGlsLmluaGVyaXRzKFJlcXVlc3QsIFN0cmVhbSk7XG5cblJlcXVlc3QucHJvdG90eXBlLmNyZWF0ZVVuaXhDb25uZWN0aW9uID0gZnVuY3Rpb24oYXV0aG9yaXR5LCBvcHRpb25zKSB7XG4gIHN3aXRjaCAodGhpcy5wcm90b2NvbCkge1xuICAgIGNhc2UgJ2h0dHA6JzpcbiAgICAgIHJldHVybiBuZXQuY29ubmVjdChvcHRpb25zLnNvY2tldFBhdGgpO1xuICAgIGNhc2UgJ2h0dHBzOic6XG4gICAgICBvcHRpb25zLkFMUE5Qcm90b2NvbHMgPSBbJ2gyJ107XG4gICAgICBvcHRpb25zLnNlcnZlcm5hbWUgPSB0aGlzLmhvc3Q7XG4gICAgICBvcHRpb25zLmFsbG93SGFsZk9wZW4gPSB0cnVlO1xuICAgICAgcmV0dXJuIHRscy5jb25uZWN0KG9wdGlvbnMuc29ja2V0UGF0aCwgb3B0aW9ucyk7XG4gICAgZGVmYXVsdDpcbiAgICAgIHRocm93IG5ldyBFcnJvcignVW5zdXBwb3J0ZWQgcHJvdG9jb2wnLCB0aGlzLnByb3RvY29sKTtcbiAgfVxufTtcblxuLy8gZXNsaW50LWRpc2FibGUtbmV4dC1saW5lIG5vLXVudXNlZC12YXJzXG5SZXF1ZXN0LnByb3RvdHlwZS5zZXROb0RlbGF5ID0gZnVuY3Rpb24oYm9vbCkge1xuICAvLyBXZSBjYW4gbm90IHVzZSBzZXROb0RlbGF5IHdpdGggSFRUUC8yLlxuICAvLyBOb2RlIDEwIGxpbWl0cyBodHRwMnNlc3Npb24uc29ja2V0IG1ldGhvZHMgdG8gb25lcyBzYWZlIHRvIHVzZSB3aXRoIEhUVFAvMi5cbiAgLy8gU2VlIGFsc28gaHR0cHM6Ly9ub2RlanMub3JnL2FwaS9odHRwMi5odG1sI2h0dHAyX2h0dHAyc2Vzc2lvbl9zb2NrZXRcbn07XG5cblJlcXVlc3QucHJvdG90eXBlLmdldEZyYW1lID0gZnVuY3Rpb24oKSB7XG4gIGlmICh0aGlzLmZyYW1lKSB7XG4gICAgcmV0dXJuIHRoaXMuZnJhbWU7XG4gIH1cblxuICBjb25zdCBtZXRob2QgPSB7XG4gICAgW0hUVFAyX0hFQURFUl9QQVRIXTogdGhpcy5wYXRoLFxuICAgIFtIVFRQMl9IRUFERVJfTUVUSE9EXTogdGhpcy5tZXRob2RcbiAgfTtcblxuICBsZXQgaGVhZGVycyA9IHRoaXMubWFwVG9IdHRwMkhlYWRlcih0aGlzLl9oZWFkZXJzKTtcblxuICBoZWFkZXJzID0gT2JqZWN0LmFzc2lnbihoZWFkZXJzLCBtZXRob2QpO1xuXG4gIGNvbnN0IGZyYW1lID0gdGhpcy5zZXNzaW9uLnJlcXVlc3QoaGVhZGVycyk7XG4gIC8vIGVzbGludC1kaXNhYmxlLW5leHQtbGluZSBuby11bnVzZWQtdmFyc1xuICBmcmFtZS5vbmNlKCdyZXNwb25zZScsIChoZWFkZXJzLCBmbGFncykgPT4ge1xuICAgIGhlYWRlcnMgPSB0aGlzLm1hcFRvSHR0cEhlYWRlcihoZWFkZXJzKTtcbiAgICBmcmFtZS5oZWFkZXJzID0gaGVhZGVycztcbiAgICBmcmFtZS5zdGF0dXNDb2RlID0gaGVhZGVyc1tIVFRQMl9IRUFERVJfU1RBVFVTXTtcbiAgICBmcmFtZS5zdGF0dXMgPSBmcmFtZS5zdGF0dXNDb2RlO1xuICAgIHRoaXMuZW1pdCgncmVzcG9uc2UnLCBmcmFtZSk7XG4gIH0pO1xuXG4gIHRoaXMuX2hlYWRlclNlbnQgPSB0cnVlO1xuXG4gIGZyYW1lLm9uY2UoJ2RyYWluJywgKCkgPT4gdGhpcy5lbWl0KCdkcmFpbicpKTtcbiAgZnJhbWUub24oJ2Vycm9yJywgZXJyID0+IHRoaXMuZW1pdCgnZXJyb3InLCBlcnIpKTtcbiAgZnJhbWUub24oJ2Nsb3NlJywgKCkgPT4gdGhpcy5zZXNzaW9uLmNsb3NlKCkpO1xuXG4gIHRoaXMuZnJhbWUgPSBmcmFtZTtcbiAgcmV0dXJuIGZyYW1lO1xufTtcblxuUmVxdWVzdC5wcm90b3R5cGUubWFwVG9IdHRwSGVhZGVyID0gZnVuY3Rpb24oaGVhZGVycykge1xuICBjb25zdCBrZXlzID0gT2JqZWN0LmtleXMoaGVhZGVycyk7XG4gIGNvbnN0IGh0dHAySGVhZGVycyA9IHt9O1xuICBmb3IgKGxldCBrZXkgb2Yga2V5cykge1xuICAgIGxldCB2YWx1ZSA9IGhlYWRlcnNba2V5XTtcbiAgICBrZXkgPSBrZXkudG9Mb3dlckNhc2UoKTtcbiAgICBzd2l0Y2ggKGtleSkge1xuICAgICAgY2FzZSBIVFRQMl9IRUFERVJfU0VUX0NPT0tJRTpcbiAgICAgICAgdmFsdWUgPSBBcnJheS5pc0FycmF5KHZhbHVlKSA/IHZhbHVlIDogW3ZhbHVlXTtcbiAgICAgICAgYnJlYWs7XG4gICAgICBkZWZhdWx0OlxuICAgICAgICBicmVhaztcbiAgICB9XG5cbiAgICBodHRwMkhlYWRlcnNba2V5XSA9IHZhbHVlO1xuICB9XG5cbiAgcmV0dXJuIGh0dHAySGVhZGVycztcbn07XG5cblJlcXVlc3QucHJvdG90eXBlLm1hcFRvSHR0cDJIZWFkZXIgPSBmdW5jdGlvbihoZWFkZXJzKSB7XG4gIGNvbnN0IGtleXMgPSBPYmplY3Qua2V5cyhoZWFkZXJzKTtcbiAgY29uc3QgaHR0cDJIZWFkZXJzID0ge307XG4gIGZvciAobGV0IGtleSBvZiBrZXlzKSB7XG4gICAgbGV0IHZhbHVlID0gaGVhZGVyc1trZXldO1xuICAgIGtleSA9IGtleS50b0xvd2VyQ2FzZSgpO1xuICAgIHN3aXRjaCAoa2V5KSB7XG4gICAgICBjYXNlIEhUVFAyX0hFQURFUl9IT1NUOlxuICAgICAgICBrZXkgPSBIVFRQMl9IRUFERVJfQVVUSE9SSVRZO1xuICAgICAgICB2YWx1ZSA9IC9eaHR0cDpcXC9cXC98Xmh0dHBzOlxcL1xcLy8udGVzdCh2YWx1ZSlcbiAgICAgICAgICA/IHBhcnNlKHZhbHVlKS5ob3N0XG4gICAgICAgICAgOiB2YWx1ZTtcbiAgICAgICAgYnJlYWs7XG4gICAgICBkZWZhdWx0OlxuICAgICAgICBicmVhaztcbiAgICB9XG5cbiAgICBodHRwMkhlYWRlcnNba2V5XSA9IHZhbHVlO1xuICB9XG5cbiAgcmV0dXJuIGh0dHAySGVhZGVycztcbn07XG5cblJlcXVlc3QucHJvdG90eXBlLnNldEhlYWRlciA9IGZ1bmN0aW9uKG5hbWUsIHZhbHVlKSB7XG4gIHRoaXMuX2hlYWRlcnNbbmFtZS50b0xvd2VyQ2FzZSgpXSA9IHZhbHVlO1xufTtcblxuUmVxdWVzdC5wcm90b3R5cGUuZ2V0SGVhZGVyID0gZnVuY3Rpb24obmFtZSkge1xuICByZXR1cm4gdGhpcy5faGVhZGVyc1tuYW1lLnRvTG93ZXJDYXNlKCldO1xufTtcblxuUmVxdWVzdC5wcm90b3R5cGUud3JpdGUgPSBmdW5jdGlvbihkYXRhLCBlbmNvZGluZykge1xuICBjb25zdCBmcmFtZSA9IHRoaXMuZ2V0RnJhbWUoKTtcbiAgcmV0dXJuIGZyYW1lLndyaXRlKGRhdGEsIGVuY29kaW5nKTtcbn07XG5cblJlcXVlc3QucHJvdG90eXBlLnBpcGUgPSBmdW5jdGlvbihzdHJlYW0sIG9wdGlvbnMpIHtcbiAgY29uc3QgZnJhbWUgPSB0aGlzLmdldEZyYW1lKCk7XG4gIHJldHVybiBmcmFtZS5waXBlKHN0cmVhbSwgb3B0aW9ucyk7XG59O1xuXG5SZXF1ZXN0LnByb3RvdHlwZS5lbmQgPSBmdW5jdGlvbihkYXRhKSB7XG4gIGNvbnN0IGZyYW1lID0gdGhpcy5nZXRGcmFtZSgpO1xuICBmcmFtZS5lbmQoZGF0YSk7XG59O1xuXG4vLyBlc2xpbnQtZGlzYWJsZS1uZXh0LWxpbmUgbm8tdW51c2VkLXZhcnNcblJlcXVlc3QucHJvdG90eXBlLmFib3J0ID0gZnVuY3Rpb24oZGF0YSkge1xuICBjb25zdCBmcmFtZSA9IHRoaXMuZ2V0RnJhbWUoKTtcbiAgZnJhbWUuY2xvc2UoTkdIVFRQMl9DQU5DRUwpO1xuICB0aGlzLnNlc3Npb24uZGVzdHJveSgpO1xufTtcblxuZXhwb3J0cy5zZXRQcm90b2NvbCA9IHNldFByb3RvY29sO1xuIl19
}, function(modId) { var map = {}; return __REQUIRE__(map[modId], modId); })
__DEFINE__(1603008214474, function(require, module, exports) {


/**
 * Module dependencies.
 */
// eslint-disable-next-line node/no-deprecated-api
var _require = require('url'),
    parse = _require.parse;

var _require2 = require('cookiejar'),
    CookieJar = _require2.CookieJar;

var _require3 = require('cookiejar'),
    CookieAccessInfo = _require3.CookieAccessInfo;

var methods = require('methods');

var request = require('../..');

var AgentBase = require('../agent-base');
/**
 * Expose `Agent`.
 */


module.exports = Agent;
/**
 * Initialize a new `Agent`.
 *
 * @api public
 */

function Agent(options) {
  if (!(this instanceof Agent)) {
    return new Agent(options);
  }

  AgentBase.call(this);
  this.jar = new CookieJar();

  if (options) {
    if (options.ca) {
      this.ca(options.ca);
    }

    if (options.key) {
      this.key(options.key);
    }

    if (options.pfx) {
      this.pfx(options.pfx);
    }

    if (options.cert) {
      this.cert(options.cert);
    }

    if (options.rejectUnauthorized === false) {
      this.disableTLSCerts();
    }
  }
}

Agent.prototype = Object.create(AgentBase.prototype);
/**
 * Save the cookies in the given `res` to
 * the agent's cookie jar for persistence.
 *
 * @param {Response} res
 * @api private
 */

Agent.prototype._saveCookies = function (res) {
  var cookies = res.headers['set-cookie'];
  if (cookies) this.jar.setCookies(cookies);
};
/**
 * Attach cookies when available to the given `req`.
 *
 * @param {Request} req
 * @api private
 */


Agent.prototype._attachCookies = function (req) {
  var url = parse(req.url);
  var access = new CookieAccessInfo(url.hostname, url.pathname, url.protocol === 'https:');
  var cookies = this.jar.getCookies(access).toValueString();
  req.cookies = cookies;
};

methods.forEach(function (name) {
  var method = name.toUpperCase();

  Agent.prototype[name] = function (url, fn) {
    var req = new request.Request(method, url);
    req.on('response', this._saveCookies.bind(this));
    req.on('redirect', this._saveCookies.bind(this));
    req.on('redirect', this._attachCookies.bind(this, req));

    this._setDefaults(req);

    this._attachCookies(req);

    if (fn) {
      req.end(fn);
    }

    return req;
  };
});
Agent.prototype.del = Agent.prototype.delete;
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbIi4uLy4uL3NyYy9ub2RlL2FnZW50LmpzIl0sIm5hbWVzIjpbInJlcXVpcmUiLCJwYXJzZSIsIkNvb2tpZUphciIsIkNvb2tpZUFjY2Vzc0luZm8iLCJtZXRob2RzIiwicmVxdWVzdCIsIkFnZW50QmFzZSIsIm1vZHVsZSIsImV4cG9ydHMiLCJBZ2VudCIsIm9wdGlvbnMiLCJjYWxsIiwiamFyIiwiY2EiLCJrZXkiLCJwZngiLCJjZXJ0IiwicmVqZWN0VW5hdXRob3JpemVkIiwiZGlzYWJsZVRMU0NlcnRzIiwicHJvdG90eXBlIiwiT2JqZWN0IiwiY3JlYXRlIiwiX3NhdmVDb29raWVzIiwicmVzIiwiY29va2llcyIsImhlYWRlcnMiLCJzZXRDb29raWVzIiwiX2F0dGFjaENvb2tpZXMiLCJyZXEiLCJ1cmwiLCJhY2Nlc3MiLCJob3N0bmFtZSIsInBhdGhuYW1lIiwicHJvdG9jb2wiLCJnZXRDb29raWVzIiwidG9WYWx1ZVN0cmluZyIsImZvckVhY2giLCJuYW1lIiwibWV0aG9kIiwidG9VcHBlckNhc2UiLCJmbiIsIlJlcXVlc3QiLCJvbiIsImJpbmQiLCJfc2V0RGVmYXVsdHMiLCJlbmQiLCJkZWwiLCJkZWxldGUiXSwibWFwcGluZ3MiOiI7O0FBQUE7OztBQUlBO2VBQ2tCQSxPQUFPLENBQUMsS0FBRCxDO0lBQWpCQyxLLFlBQUFBLEs7O2dCQUNjRCxPQUFPLENBQUMsV0FBRCxDO0lBQXJCRSxTLGFBQUFBLFM7O2dCQUNxQkYsT0FBTyxDQUFDLFdBQUQsQztJQUE1QkcsZ0IsYUFBQUEsZ0I7O0FBQ1IsSUFBTUMsT0FBTyxHQUFHSixPQUFPLENBQUMsU0FBRCxDQUF2Qjs7QUFDQSxJQUFNSyxPQUFPLEdBQUdMLE9BQU8sQ0FBQyxPQUFELENBQXZCOztBQUNBLElBQU1NLFNBQVMsR0FBR04sT0FBTyxDQUFDLGVBQUQsQ0FBekI7QUFFQTs7Ozs7QUFJQU8sTUFBTSxDQUFDQyxPQUFQLEdBQWlCQyxLQUFqQjtBQUVBOzs7Ozs7QUFNQSxTQUFTQSxLQUFULENB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R0FBcEI7O0FBRUEsUUFBSVksRUFBSixFQUFRO0FBQ05aLE1BQUFBLEdBQUcsQ0FBQ2lCLEdBQUosQ0FBUUwsRUFBUjtBQUNEOztBQUVELFdBQU9aLEdBQVA7QUFDRCxHQWREO0FBZUQsQ0FqQkQ7QUFtQkFuQixLQUFLLENBQUNVLFNBQU4sQ0FBZ0IyQixHQUFoQixHQUFzQnJDLEtBQUssQ0FBQ1UsU0FBTixDQUFnQjRCLE1BQXRDIiwic291cmNlc0NvbnRlbnQiOlsiLyoqXG4gKiBNb2R1bGUgZGVwZW5kZW5jaWVzLlxuICovXG5cbi8vIGVzbGludC1kaXNhYmxlLW5leHQtbGluZSBub2RlL25vLWRlcHJlY2F0ZWQtYXBpXG5jb25zdCB7IHBhcnNlIH0gPSByZXF1aXJlKCd1cmwnKTtcbmNvbnN0IHsgQ29va2llSmFyIH0gPSByZXF1aXJlKCdjb29raWVqYXInKTtcbmNvbnN0IHsgQ29va2llQWNjZXNzSW5mbyB9ID0gcmVxdWlyZSgnY29va2llamFyJyk7XG5jb25zdCBtZXRob2RzID0gcmVxdWlyZSgnbWV0aG9kcycpO1xuY29uc3QgcmVxdWVzdCA9IHJlcXVpcmUoJy4uLy4uJyk7XG5jb25zdCBBZ2VudEJhc2UgPSByZXF1aXJlKCcuLi9hZ2VudC1iYXNlJyk7XG5cbi8qKlxuICogRXhwb3NlIGBBZ2VudGAuXG4gKi9cblxubW9kdWxlLmV4cG9ydHMgPSBBZ2VudDtcblxuLyoqXG4gKiBJbml0aWFsaXplIGEgbmV3IGBBZ2VudGAuXG4gKlxuICogQGFwaSBwdWJsaWNcbiAqL1xuXG5mdW5jdGlvbiBBZ2VudChvcHRpb25zKSB7XG4gIGlmICghKHRoaXMgaW5zdGFuY2VvZiBBZ2VudCkpIHtcbiAgICByZXR1cm4gbmV3IEFnZW50KG9wdGlvbnMpO1xuICB9XG5cbiAgQWdlbnRCYXNlLmNhbGwodGhpcyk7XG4gIHRoaXMuamFyID0gbmV3IENvb2tpZUphcigpO1xuXG4gIGlmIChvcHRpb25zKSB7XG4gICAgaWYgKG9wdGlvbnMuY2EpIHtcbiAgICAgIHRoaXMuY2Eob3B0aW9ucy5jYSk7XG4gICAgfVxuXG4gICAgaWYgKG9wdGlvbnMua2V5KSB7XG4gICAgICB0aGlzLmtleShvcHRpb25zLmtleSk7XG4gICAgfVxuXG4gICAgaWYgKG9wdGlvbnMucGZ4KSB7XG4gICAgICB0aGlzLnBmeChvcHRpb25zLnBmeCk7XG4gICAgfVxuXG4gICAgaWYgKG9wdGlvbnMuY2VydCkge1xuICAgICAgdGhpcy5jZXJ0KG9wdGlvbnMuY2VydCk7XG4gICAgfVxuXG4gICAgaWYgKG9wdGlvbnMucmVqZWN0VW5hdXRob3JpemVkID09PSBmYWxzZSkge1xuICAgICAgdGhpcy5kaXNhYmxlVExTQ2VydHMoKTtcbiAgICB9XG4gIH1cbn1cblxuQWdlbnQucHJvdG90eXBlID0gT2JqZWN0LmNyZWF0ZShBZ2VudEJhc2UucHJvdG90eXBlKTtcblxuLyoqXG4gKiBTYXZlIHRoZSBjb29raWVzIGluIHRoZSBnaXZlbiBgcmVzYCB0b1xuICogdGhlIGFnZW50J3MgY29va2llIGphciBmb3IgcGVyc2lzdGVuY2UuXG4gKlxuICogQHBhcmFtIHtSZXNwb25zZX0gcmVzXG4gKiBAYXBpIHByaXZhdGVcbiAqL1xuXG5BZ2VudC5wcm90b3R5cGUuX3NhdmVDb29raWVzID0gZnVuY3Rpb24ocmVzKSB7XG4gIGNvbnN0IGNvb2tpZXMgPSByZXMuaGVhZGVyc1snc2V0LWNvb2tpZSddO1xuICBpZiAoY29va2llcykgdGhpcy5qYXIuc2V0Q29va2llcyhjb29raWVzKTtcbn07XG5cbi8qKlxuICogQXR0YWNoIGNvb2tpZXMgd2hlbiBhdmFpbGFibGUgdG8gdGhlIGdpdmVuIGByZXFgLlxuICpcbiAqIEBwYXJhbSB7UmVxdWVzdH0gcmVxXG4gKiBAYXBpIHByaXZhdGVcbiAqL1xuXG5BZ2VudC5wcm90b3R5cGUuX2F0dGFjaENvb2tpZXMgPSBmdW5jdGlvbihyZXEpIHtcbiAgY29uc3QgdXJsID0gcGFyc2UocmVxLnVybCk7XG4gIGNvbnN0IGFjY2VzcyA9IG5ldyBDb29raWVBY2Nlc3NJbmZvKFxuICAgIHVybC5ob3N0bmFtZSxcbiAgICB1cmwucGF0aG5hbWUsXG4gICAgdXJsLnByb3RvY29sID09PSAnaHR0cHM6J1xuICApO1xuICBjb25zdCBjb29raWVzID0gdGhpcy5qYXIuZ2V0Q29va2llcyhhY2Nlc3MpLnRvVmFsdWVTdHJpbmcoKTtcbiAgcmVxLmNvb2tpZXMgPSBjb29raWVzO1xufTtcblxubWV0aG9kcy5mb3JFYWNoKG5hbWUgPT4ge1xuICBjb25zdCBtZXRob2QgPSBuYW1lLnRvVXBwZXJDYXNlKCk7XG4gIEFnZW50LnByb3RvdHlwZVtuYW1lXSA9IGZ1bmN0aW9uKHVybCwgZm4pIHtcbiAgICBjb25zdCByZXEgPSBuZXcgcmVxdWVzdC5SZXF1ZXN0KG1ldGhvZCwgdXJsKTtcblxuICAgIHJlcS5vbigncmVzcG9uc2UnLCB0aGlzLl9zYXZlQ29va2llcy5iaW5kKHRoaXMpKTtcbiAgICByZXEub24oJ3JlZGlyZWN0JywgdGhpcy5fc2F2ZUNvb2tpZXMuYmluZCh0aGlzKSk7XG4gICAgcmVxLm9uKCdyZWRpcmVjdCcsIHRoaXMuX2F0dGFjaENvb2tpZXMuYmluZCh0aGlzLCByZXEpKTtcbiAgICB0aGlzLl9zZXREZWZhdWx0cyhyZXEpO1xuICAgIHRoaXMuX2F0dGFjaENvb2tpZXMocmVxKTtcblxuICAgIGlmIChmbikge1xuICAgICAgcmVxLmVuZChmbik7XG4gICAgfVxuXG4gICAgcmV0dXJuIHJlcTtcbiAgfTtcbn0pO1xuXG5BZ2VudC5wcm90b3R5cGUuZGVsID0gQWdlbnQucHJvdG90eXBlLmRlbGV0ZTtcbiJdfQ==
}, function(modId) { var map = {"../agent-base":1603008214475}; return __REQUIRE__(map[modId], modId); })
__DEFINE__(1603008214475, function(require, module, exports) {


function _toConsumableArray(arr) { return _arrayWithoutHoles(arr) || _iterableToArray(arr) || _unsupportedIterableToArray(arr) || _nonIterableSpread(); }

function _nonIterableSpread() { throw new TypeError("Invalid attempt to spread non-iterable instance.\nIn order to be iterable, non-array objects must have a [Symbol.iterator]() method."); }

function _unsupportedIterableToArray(o, minLen) { if (!o) return; if (typeof o === "string") return _arrayLikeToArray(o, minLen); var n = Object.prototype.toString.call(o).slice(8, -1); if (n === "Object" && o.constructor) n = o.constructor.name; if (n === "Map" || n === "Set") return Array.from(o); if (n === "Arguments" || /^(?:Ui|I)nt(?:8|16|32)(?:Clamped)?Array$/.test(n)) return _arrayLikeToArray(o, minLen); }

function _iterableToArray(iter) { if (typeof Symbol !== "undefined" && Symbol.iterator in Object(iter)) return Array.from(iter); }

function _arrayWithoutHoles(arr) { if (Array.isArray(arr)) return _arrayLikeToArray(arr); }

function _arrayLikeToArray(arr, len) { if (len == null || len > arr.length) len = arr.length; for (var i = 0, arr2 = new Array(len); i < len; i++) { arr2[i] = arr[i]; } return arr2; }

function Agent() {
  this._defaults = [];
}

['use', 'on', 'once', 'set', 'query', 'type', 'accept', 'auth', 'withCredentials', 'sortQuery', 'retry', 'ok', 'redirects', 'timeout', 'buffer', 'serialize', 'parse', 'ca', 'key', 'pfx', 'cert', 'disableTLSCerts'].forEach(function (fn) {
  // Default setting for all requests from this agent
  Agent.prototype[fn] = function () {
    for (var _len = arguments.length, args = new Array(_len), _key = 0; _key < _len; _key++) {
      args[_key] = arguments[_key];
    }

    this._defaults.push({
      fn: fn,
      args: args
    });

    return this;
  };
});

Agent.prototype._setDefaults = function (req) {
  this._defaults.forEach(function (def) {
    req[def.fn].apply(req, _toConsumableArray(def.args));
  });
};

module.exports = Agent;
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbIi4uL3NyYy9hZ2VudC1iYXNlLmpzIl0sIm5hbWVzIjpbIkFnZW50IiwiX2RlZmF1bHRzIiwiZm9yRWFjaCIsImZuIiwicHJvdG90eXBlIiwiYXJncyIsInB1c2giLCJfc2V0RGVmYXVsdHMiLCJyZXEiLCJkZWYiLCJtb2R1bGUiLCJleHBvcnRzIl0sIm1hcHBpbmdzIjoiOzs7Ozs7Ozs7Ozs7OztBQUFBLFNBQVNBLEtBQVQsR0FBaUI7QUFDZixPQUFLQyxTQUFMLEdBQWlCLEVBQWpCO0FBQ0Q7O0FBRUQsQ0FDRSxLQURGLEVBRUUsSUFGRixFQUdFLE1BSEYsRUFJRSxLQUpGLEVBS0UsT0FMRixFQU1FLE1BTkYsRUFPRSxRQVBGLEVBUUUsTUFSRixFQVNFLGlCQVRGLEVBVUUsV0FWRixFQVdFLE9BWEYsRUFZRSxJQVpGLEVBYUUsV0FiRixFQWNFLFNBZEYsRUFlRSxRQWZGLEVBZ0JFLFdBaEJGLEVBaUJFLE9BakJGLEVBa0JFLElBbEJGLEVBbUJFLEtBbkJGLEVBb0JFLEtBcEJGLEVBcUJFLE1BckJGLEVBc0JFLGlCQXRCRixFQXVCRUMsT0F2QkYsQ0F1QlUsVUFBQUMsRUFBRSxFQUFJO0FBQ2Q7QUFDQUgsRUFBQUEsS0FBSyxDQUFDSSxTQUFOLENBQWdCRCxFQUFoQixJQUFzQixZQUFrQjtBQUFBLHNDQUFORSxJQUFNO0FBQU5BLE1BQUFBLElBQU07QUFBQTs7QUFDdEMsU0FBS0osU0FBTCxDQUFlSyxJQUFmLENBQW9CO0FBQUVILE1BQUFBLEVBQUUsRUFBRkEsRUFBRjtBQUFNRSxNQUFBQSxJQUFJLEVBQUpBO0FBQU4sS0FBcEI7O0FBQ0EsV0FBTyxJQUFQO0FBQ0QsR0FIRDtBQUlELENBN0JEOztBQStCQUwsS0FBSyxDQUFDSSxTQUFOLENBQWdCRyxZQUFoQixHQUErQixVQUFTQyxHQUFULEVBQWM7QUFDM0MsT0FBS1AsU0FBTCxDQUFlQyxPQUFmLENBQXVCLFVBQUFPLEdBQUcsRUFBSTtBQUM1QkQsSUFBQUEsR0FBRyxDQUFDQyxHQUFHLENBQUNOLEVBQUwsQ0FBSCxPQUFBSyxHQUFHLHFCQUFZQyxHQUFHLENBQUNKLElBQWhCLEVBQUg7QUFDRCxHQUZEO0FBR0QsQ0FKRDs7QUFNQUssTUFBTSxDQUFDQyxPQUFQLEdBQWlCWCxLQUFqQiIsInNvdXJjZXNDb250ZW50IjpbImZ1bmN0aW9uIEFnZW50KCkge1xuICB0aGlzLl9kZWZhdWx0cyA9IFtdO1xufVxuXG5bXG4gICd1c2UnLFxuICAnb24nLFxuICAnb25jZScsXG4gICdzZXQnLFxuICAncXVlcnknLFxuICAndHlwZScsXG4gICdhY2NlcHQnLFxuICAnYXV0aCcsXG4gICd3aXRoQ3JlZGVudGlhbHMnLFxuICAnc29ydFF1ZXJ5JyxcbiAgJ3JldHJ5JyxcbiAgJ29rJyxcbiAgJ3JlZGlyZWN0cycsXG4gICd0aW1lb3V0JyxcbiAgJ2J1ZmZlcicsXG4gICdzZXJpYWxpemUnLFxuICAncGFyc2UnLFxuICAnY2EnLFxuICAna2V5JyxcbiAgJ3BmeCcsXG4gICdjZXJ0JyxcbiAgJ2Rpc2FibGVUTFNDZXJ0cydcbl0uZm9yRWFjaChmbiA9PiB7XG4gIC8vIERlZmF1bHQgc2V0dGluZyBmb3IgYWxsIHJlcXVlc3RzIGZyb20gdGhpcyBhZ2VudFxuICBBZ2VudC5wcm90b3R5cGVbZm5dID0gZnVuY3Rpb24oLi4uYXJncykge1xuICAgIHRoaXMuX2RlZmF1bHRzLnB1c2goeyBmbiwgYXJncyB9KTtcbiAgICByZXR1cm4gdGhpcztcbiAgfTtcbn0pO1xuXG5BZ2VudC5wcm90b3R5cGUuX3NldERlZmF1bHRzID0gZnVuY3Rpb24ocmVxKSB7XG4gIHRoaXMuX2RlZmF1bHRzLmZvckVhY2goZGVmID0+IHtcbiAgICByZXFbZGVmLmZuXSguLi5kZWYuYXJncyk7XG4gIH0pO1xufTtcblxubW9kdWxlLmV4cG9ydHMgPSBBZ2VudDtcbiJdfQ==
}, function(modId) { var map = {}; return __REQUIRE__(map[modId], modId); })
__DEFINE__(1603008214476, function(require, module, exports) {


exports['application/x-www-form-urlencoded'] = require('./urlencoded');
exports['application/json'] = require('./json');
exports.text = require('./text');

var binary = require('./image');

exports['application/octet-stream'] = binary;
exports['application/pdf'] = binary;
exports.image = binary;
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbIi4uLy4uLy4uL3NyYy9ub2RlL3BhcnNlcnMvaW5kZXguanMiXSwibmFtZXMiOlsiZXhwb3J0cyIsInJlcXVpcmUiLCJ0ZXh0IiwiYmluYXJ5IiwiaW1hZ2UiXSwibWFwcGluZ3MiOiI7O0FBQUFBLE9BQU8sQ0FBQyxtQ0FBRCxDQUFQLEdBQStDQyxPQUFPLENBQUMsY0FBRCxDQUF0RDtBQUNBRCxPQUFPLENBQUMsa0JBQUQsQ0FBUCxHQUE4QkMsT0FBTyxDQUFDLFFBQUQsQ0FBckM7QUFDQUQsT0FBTyxDQUFDRSxJQUFSLEdBQWVELE9BQU8sQ0FBQyxRQUFELENBQXRCOztBQUVBLElBQU1FLE1BQU0sR0FBR0YsT0FBTyxDQUFDLFNBQUQsQ0FBdEI7O0FBRUFELE9BQU8sQ0FBQywwQkFBRCxDQUFQLEdBQXNDRyxNQUF0QztBQUNBSCxPQUFPLENBQUMsaUJBQUQsQ0FBUCxHQUE2QkcsTUFBN0I7QUFDQUgsT0FBTyxDQUFDSSxLQUFSLEdBQWdCRCxNQUFoQiIsInNvdXJjZXNDb250ZW50IjpbImV4cG9ydHNbJ2FwcGxpY2F0aW9uL3gtd3d3LWZvcm0tdXJsZW5jb2RlZCddID0gcmVxdWlyZSgnLi91cmxlbmNvZGVkJyk7XG5leHBvcnRzWydhcHBsaWNhdGlvbi9qc29uJ10gPSByZXF1aXJlKCcuL2pzb24nKTtcbmV4cG9ydHMudGV4dCA9IHJlcXVpcmUoJy4vdGV4dCcpO1xuXG5jb25zdCBiaW5hcnkgPSByZXF1aXJlKCcuL2ltYWdlJyk7XG5cbmV4cG9ydHNbJ2FwcGxpY2F0aW9uL29jdGV0LXN0cmVhbSddID0gYmluYXJ5O1xuZXhwb3J0c1snYXBwbGljYXRpb24vcGRmJ10gPSBiaW5hcnk7XG5leHBvcnRzLmltYWdlID0gYmluYXJ5O1xuIl19
}, function(modId) { var map = {"./urlencoded":1603008214477,"./json":1603008214478,"./text":1603008214479,"./image":1603008214480}; return __REQUIRE__(map[modId], modId); })
__DEFINE__(1603008214477, function(require, module, exports) {


/**
 * Module dependencies.
 */
var qs = require('qs');

module.exports = function (res, fn) {
  res.text = '';
  res.setEncoding('ascii');
  res.on('data', function (chunk) {
    res.text += chunk;
  });
  res.on('end', function () {
    try {
      fn(null, qs.parse(res.text));
    } catch (err) {
      fn(err);
    }
  });
};
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbIi4uLy4uLy4uL3NyYy9ub2RlL3BhcnNlcnMvdXJsZW5jb2RlZC5qcyJdLCJuYW1lcyI6WyJxcyIsInJlcXVpcmUiLCJtb2R1bGUiLCJleHBvcnRzIiwicmVzIiwiZm4iLCJ0ZXh0Iiwic2V0RW5jb2RpbmciLCJvbiIsImNodW5rIiwicGFyc2UiLCJlcnIiXSwibWFwcGluZ3MiOiI7O0FBQUE7OztBQUlBLElBQU1BLEVBQUUsR0FBR0MsT0FBTyxDQUFDLElBQUQsQ0FBbEI7O0FBRUFDLE1BQU0sQ0FBQ0MsT0FBUCxHQUFpQixVQUFDQyxHQUFELEVBQU1DLEVBQU4sRUFBYTtBQUM1QkQsRUFBQUEsR0FBRyxDQUFDRSxJQUFKLEdBQVcsRUFBWDtBQUNBRixFQUFBQSxHQUFHLENBQUNHLFdBQUosQ0FBZ0IsT0FBaEI7QUFDQUgsRUFBQUEsR0FBRyxDQUFDSSxFQUFKLENBQU8sTUFBUCxFQUFlLFVBQUFDLEtBQUssRUFBSTtBQUN0QkwsSUFBQUEsR0FBRyxDQUFDRSxJQUFKLElBQVlHLEtBQVo7QUFDRCxHQUZEO0FBR0FMLEVBQUFBLEdBQUcsQ0FBQ0ksRUFBSixDQUFPLEtBQVAsRUFBYyxZQUFNO0FBQ2xCLFFBQUk7QUFDRkgsTUFBQUEsRUFBRSxDQUFDLElBQUQsRUFBT0wsRUFBRSxDQUFDVSxLQUFILENBQVNOLEdBQUcsQ0FBQ0UsSUFBYixDQUFQLENBQUY7QUFDRCxLQUZELENBRUUsT0FBT0ssR0FBUCxFQUFZO0FBQ1pOLE1BQUFBLEVBQUUsQ0FBQ00sR0FBRCxDQUFGO0FBQ0Q7QUFDRixHQU5EO0FBT0QsQ0FiRCIsInNvdXJjZXNDb250ZW50IjpbIi8qKlxuICogTW9kdWxlIGRlcGVuZGVuY2llcy5cbiAqL1xuXG5jb25zdCBxcyA9IHJlcXVpcmUoJ3FzJyk7XG5cbm1vZHVsZS5leHBvcnRzID0gKHJlcywgZm4pID0+IHtcbiAgcmVzLnRleHQgPSAnJztcbiAgcmVzLnNldEVuY29kaW5nKCdhc2NpaScpO1xuICByZXMub24oJ2RhdGEnLCBjaHVuayA9PiB7XG4gICAgcmVzLnRleHQgKz0gY2h1bms7XG4gIH0pO1xuICByZXMub24oJ2VuZCcsICgpID0+IHtcbiAgICB0cnkge1xuICAgICAgZm4obnVsbCwgcXMucGFyc2UocmVzLnRleHQpKTtcbiAgICB9IGNhdGNoIChlcnIpIHtcbiAgICAgIGZuKGVycik7XG4gICAgfVxuICB9KTtcbn07XG4iXX0=
}, function(modId) { var map = {}; return __REQUIRE__(map[modId], modId); })
__DEFINE__(1603008214478, function(require, module, exports) {


module.exports = function (res, fn) {
  res.text = '';
  res.setEncoding('utf8');
  res.on('data', function (chunk) {
    res.text += chunk;
  });
  res.on('end', function () {
    var body;
    var err;

    try {
      body = res.text && JSON.parse(res.text);
    } catch (err_) {
      err = err_; // issue #675: return the raw response if the response parsing fails

      err.rawResponse = res.text || null; // issue #876: return the http status code if the response parsing fails

      err.statusCode = res.statusCode;
    } finally {
      fn(err, body);
    }
  });
};
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbIi4uLy4uLy4uL3NyYy9ub2RlL3BhcnNlcnMvanNvbi5qcyJdLCJuYW1lcyI6WyJtb2R1bGUiLCJleHBvcnRzIiwicmVzIiwiZm4iLCJ0ZXh0Iiwic2V0RW5jb2RpbmciLCJvbiIsImNodW5rIiwiYm9keSIsImVyciIsIkpTT04iLCJwYXJzZSIsImVycl8iLCJyYXdSZXNwb25zZSIsInN0YXR1c0NvZGUiXSwibWFwcGluZ3MiOiI7O0FBQUFBLE1BQU0sQ0FBQ0MsT0FBUCxHQUFpQixVQUFTQyxHQUFULEVBQWNDLEVBQWQsRUFBa0I7QUFDakNELEVBQUFBLEdBQUcsQ0FBQ0UsSUFBSixHQUFXLEVBQVg7QUFDQUYsRUFBQUEsR0FBRyxDQUFDRyxXQUFKLENBQWdCLE1BQWhCO0FBQ0FILEVBQUFBLEdBQUcsQ0FBQ0ksRUFBSixDQUFPLE1BQVAsRUFBZSxVQUFBQyxLQUFLLEVBQUk7QUFDdEJMLElBQUFBLEdBQUcsQ0FBQ0UsSUFBSixJQUFZRyxLQUFaO0FBQ0QsR0FGRDtBQUdBTCxFQUFBQSxHQUFHLENBQUNJLEVBQUosQ0FBTyxLQUFQLEVBQWMsWUFBTTtBQUNsQixRQUFJRSxJQUFKO0FBQ0EsUUFBSUMsR0FBSjs7QUFDQSxRQUFJO0FBQ0ZELE1BQUFBLElBQUksR0FBR04sR0FBRyxDQUFDRSxJQUFKLElBQVlNLElBQUksQ0FBQ0MsS0FBTCxDQUFXVCxHQUFHLENBQUNFLElBQWYsQ0FBbkI7QUFDRCxLQUZELENBRUUsT0FBT1EsSUFBUCxFQUFhO0FBQ2JILE1BQUFBLEdBQUcsR0FBR0csSUFBTixDQURhLENBRWI7O0FBQ0FILE1BQUFBLEdBQUcsQ0FBQ0ksV0FBSixHQUFrQlgsR0FBRyxDQUFDRSxJQUFKLElBQVksSUFBOUIsQ0FIYSxDQUliOztBQUNBSyxNQUFBQSxHQUFHLENBQUNLLFVBQUosR0FBaUJaLEdBQUcsQ0FBQ1ksVUFBckI7QUFDRCxLQVJELFNBUVU7QUFDUlgsTUFBQUEsRUFBRSxDQUFDTSxHQUFELEVBQU1ELElBQU4sQ0FBRjtBQUNEO0FBQ0YsR0FkRDtBQWVELENBckJEIiwic291cmNlc0NvbnRlbnQiOlsibW9kdWxlLmV4cG9ydHMgPSBmdW5jdGlvbihyZXMsIGZuKSB7XG4gIHJlcy50ZXh0ID0gJyc7XG4gIHJlcy5zZXRFbmNvZGluZygndXRmOCcpO1xuICByZXMub24oJ2RhdGEnLCBjaHVuayA9PiB7XG4gICAgcmVzLnRleHQgKz0gY2h1bms7XG4gIH0pO1xuICByZXMub24oJ2VuZCcsICgpID0+IHtcbiAgICBsZXQgYm9keTtcbiAgICBsZXQgZXJyO1xuICAgIHRyeSB7XG4gICAgICBib2R5ID0gcmVzLnRleHQgJiYgSlNPTi5wYXJzZShyZXMudGV4dCk7XG4gICAgfSBjYXRjaCAoZXJyXykge1xuICAgICAgZXJyID0gZXJyXztcbiAgICAgIC8vIGlzc3VlICM2NzU6IHJldHVybiB0aGUgcmF3IHJlc3BvbnNlIGlmIHRoZSByZXNwb25zZSBwYXJzaW5nIGZhaWxzXG4gICAgICBlcnIucmF3UmVzcG9uc2UgPSByZXMudGV4dCB8fCBudWxsO1xuICAgICAgLy8gaXNzdWUgIzg3NjogcmV0dXJuIHRoZSBodHRwIHN0YXR1cyBjb2RlIGlmIHRoZSByZXNwb25zZSBwYXJzaW5nIGZhaWxzXG4gICAgICBlcnIuc3RhdHVzQ29kZSA9IHJlcy5zdGF0dXNDb2RlO1xuICAgIH0gZmluYWxseSB7XG4gICAgICBmbihlcnIsIGJvZHkpO1xuICAgIH1cbiAgfSk7XG59O1xuIl19
}, function(modId) { var map = {}; return __REQUIRE__(map[modId], modId); })
__DEFINE__(1603008214479, function(require, module, exports) {


module.exports = function (res, fn) {
  res.text = '';
  res.setEncoding('utf8');
  res.on('data', function (chunk) {
    res.text += chunk;
  });
  res.on('end', fn);
};
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbIi4uLy4uLy4uL3NyYy9ub2RlL3BhcnNlcnMvdGV4dC5qcyJdLCJuYW1lcyI6WyJtb2R1bGUiLCJleHBvcnRzIiwicmVzIiwiZm4iLCJ0ZXh0Iiwic2V0RW5jb2RpbmciLCJvbiIsImNodW5rIl0sIm1hcHBpbmdzIjoiOztBQUFBQSxNQUFNLENBQUNDLE9BQVAsR0FBaUIsVUFBQ0MsR0FBRCxFQUFNQyxFQUFOLEVBQWE7QUFDNUJELEVBQUFBLEdBQUcsQ0FBQ0UsSUFBSixHQUFXLEVBQVg7QUFDQUYsRUFBQUEsR0FBRyxDQUFDRyxXQUFKLENBQWdCLE1BQWhCO0FBQ0FILEVBQUFBLEdBQUcsQ0FBQ0ksRUFBSixDQUFPLE1BQVAsRUFBZSxVQUFBQyxLQUFLLEVBQUk7QUFDdEJMLElBQUFBLEdBQUcsQ0FBQ0UsSUFBSixJQUFZRyxLQUFaO0FBQ0QsR0FGRDtBQUdBTCxFQUFBQSxHQUFHLENBQUNJLEVBQUosQ0FBTyxLQUFQLEVBQWNILEVBQWQ7QUFDRCxDQVBEIiwic291cmNlc0NvbnRlbnQiOlsibW9kdWxlLmV4cG9ydHMgPSAocmVzLCBmbikgPT4ge1xuICByZXMudGV4dCA9ICcnO1xuICByZXMuc2V0RW5jb2RpbmcoJ3V0ZjgnKTtcbiAgcmVzLm9uKCdkYXRhJywgY2h1bmsgPT4ge1xuICAgIHJlcy50ZXh0ICs9IGNodW5rO1xuICB9KTtcbiAgcmVzLm9uKCdlbmQnLCBmbik7XG59O1xuIl19
}, function(modId) { var map = {}; return __REQUIRE__(map[modId], modId); })
__DEFINE__(1603008214480, function(require, module, exports) {


module.exports = function (res, fn) {
  var data = []; // Binary data needs binary storage

  res.on('data', function (chunk) {
    data.push(chunk);
  });
  res.on('end', function () {
    fn(null, Buffer.concat(data));
  });
};
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbIi4uLy4uLy4uL3NyYy9ub2RlL3BhcnNlcnMvaW1hZ2UuanMiXSwibmFtZXMiOlsibW9kdWxlIiwiZXhwb3J0cyIsInJlcyIsImZuIiwiZGF0YSIsIm9uIiwiY2h1bmsiLCJwdXNoIiwiQnVmZmVyIiwiY29uY2F0Il0sIm1hcHBpbmdzIjoiOztBQUFBQSxNQUFNLENBQUNDLE9BQVAsR0FBaUIsVUFBQ0MsR0FBRCxFQUFNQyxFQUFOLEVBQWE7QUFDNUIsTUFBTUMsSUFBSSxHQUFHLEVBQWIsQ0FENEIsQ0FDWDs7QUFFakJGLEVBQUFBLEdBQUcsQ0FBQ0csRUFBSixDQUFPLE1BQVAsRUFBZSxVQUFBQyxLQUFLLEVBQUk7QUFDdEJGLElBQUFBLElBQUksQ0FBQ0csSUFBTCxDQUFVRCxLQUFWO0FBQ0QsR0FGRDtBQUdBSixFQUFBQSxHQUFHLENBQUNHLEVBQUosQ0FBTyxLQUFQLEVBQWMsWUFBTTtBQUNsQkYsSUFBQUEsRUFBRSxDQUFDLElBQUQsRUFBT0ssTUFBTSxDQUFDQyxNQUFQLENBQWNMLElBQWQsQ0FBUCxDQUFGO0FBQ0QsR0FGRDtBQUdELENBVEQiLCJzb3VyY2VzQ29udGVudCI6WyJtb2R1bGUuZXhwb3J0cyA9IChyZXMsIGZuKSA9PiB7XG4gIGNvbnN0IGRhdGEgPSBbXTsgLy8gQmluYXJ5IGRhdGEgbmVlZHMgYmluYXJ5IHN0b3JhZ2VcblxuICByZXMub24oJ2RhdGEnLCBjaHVuayA9PiB7XG4gICAgZGF0YS5wdXNoKGNodW5rKTtcbiAgfSk7XG4gIHJlcy5vbignZW5kJywgKCkgPT4ge1xuICAgIGZuKG51bGwsIEJ1ZmZlci5jb25jYXQoZGF0YSkpO1xuICB9KTtcbn07XG4iXX0=
}, function(modId) { var map = {}; return __REQUIRE__(map[modId], modId); })
return __REQUIRE__(1603008214466);
})()
//# sourceMappingURL=index.js.map
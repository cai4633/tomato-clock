module.exports = (function() {
var __MODS__ = {};
var __DEFINE__ = function(modId, func, req) { var m = { exports: {}, _tempexports: {} }; __MODS__[modId] = { status: 0, func: func, req: req, m: m }; };
var __REQUIRE__ = function(modId, source) { if(!__MODS__[modId]) return require(source); if(!__MODS__[modId].status) { var m = __MODS__[modId].m; m._exports = m._tempexports; var desp = Object.getOwnPropertyDescriptor(m, "exports"); if (desp && desp.configurable) Object.defineProperty(m, "exports", { set: function (val) { if(typeof val === "object" && val !== m._exports) { m._exports.__proto__ = val.__proto__; Object.keys(val).forEach(function (k) { m._exports[k] = val[k]; }); } m._tempexports = val }, get: function () { return m._tempexports; } }); __MODS__[modId].status = 1; __MODS__[modId].func(__MODS__[modId].req, m, m.exports); } return __MODS__[modId].m.exports; };
var __REQUIRE_WILDCARD__ = function(obj) { if(obj && obj.__esModule) { return obj; } else { var newObj = {}; if(obj != null) { for(var k in obj) { if (Object.prototype.hasOwnProperty.call(obj, k)) newObj[k] = obj[k]; } } newObj.default = obj; return newObj; } };
var __REQUIRE_DEFAULT__ = function(obj) { return obj && obj.__esModule ? obj.default : obj; };
__DEFINE__(1603008214503, function(require, module, exports) {
var assert = require('assert')
var Completion = require('./lib/completion')
var Parser = require('./lib/parser')
var path = require('path')
var tokenizeArgString = require('./lib/tokenize-arg-string')
var Usage = require('./lib/usage')
var Validation = require('./lib/validation')
var Y18n = require('y18n')

Argv(process.argv.slice(2))

var exports = module.exports = Argv
function Argv (processArgs, cwd) {
  processArgs = processArgs || [] // handle calling yargs().

  var self = {}
  var completion = null
  var usage = null
  var validation = null
  var y18n = Y18n({
    directory: path.resolve(__dirname, './locales'),
    updateFiles: false
  })

  if (!cwd) cwd = process.cwd()

  self.$0 = process.argv
    .slice(0, 2)
    .map(function (x, i) {
      // ignore the node bin, specify this in your
      // bin file with #!/usr/bin/env node
      if (i === 0 && /\b(node|iojs)$/.test(x)) return
      var b = rebase(cwd, x)
      return x.match(/^\//) && b.length < x.length ? b : x
    })
    .join(' ').trim()

  if (process.env._ !== undefined && process.argv[1] === process.env._) {
    self.$0 = process.env._.replace(
      path.dirname(process.execPath) + '/', ''
    )
  }

  var options
  self.resetOptions = self.reset = function () {
    // put yargs back into its initial
    // state, this is useful for creating a
    // nested CLI.
    options = {
      array: [],
      boolean: [],
      string: [],
      narg: {},
      key: {},
      alias: {},
      default: {},
      defaultDescription: {},
      choices: {},
      requiresArg: [],
      count: [],
      normalize: [],
      config: {},
      envPrefix: undefined
    }

    usage = Usage(self, y18n) // handle usage output.
    validation = Validation(self, usage, y18n) // handle arg validation.
    completion = Completion(self, usage)

    demanded = {}
    groups = {}

    exitProcess = true
    strict = false
    helpOpt = null
    versionOpt = null
    commandHandlers = {}
    self.parsed = false

    return self
  }
  self.resetOptions()

  self.boolean = function (bools) {
    options.boolean.push.apply(options.boolean, [].concat(bools))
    return self
  }

  self.array = function (arrays) {
    options.array.push.apply(options.array, [].concat(arrays))
    return self
  }

  self.nargs = function (key, n) {
    if (typeof key === 'object') {
      Object.keys(key).forEach(function (k) {
        self.nargs(k, key[k])
      })
    } else {
      options.narg[key] = n
    }
    return self
  }

  self.choices = function (key, values) {
    if (typeof key === 'object') {
      Object.keys(key).forEach(function (k) {
        self.choices(k, key[k])
      })
    } else {
      options.choices[key] = (options.choices[key] || []).concat(values)
    }
    return self
  }

  self.normalize = function (strings) {
    options.normalize.push.apply(options.normalize, [].concat(strings))
    return self
  }

  self.config = function (key, msg, parseFn) {
    if (typeof msg === 'function') {
      parseFn = msg
      msg = null
    }
    self.describe(key, msg || usage.deferY18nLookup('Path to JSON config file'))
    ;(Array.isArray(key) ? key : [key]).forEach(function (k) {
      options.config[k] = parseFn || true
    })
    return self
  }

  self.example = function (cmd, description) {
    usage.example(cmd, description)
    return self
  }

  self.command = function (cmd, description, fn) {
    if (description !== false) {
      usage.command(cmd, description)
    }
    if (fn) commandHandlers[cmd] = fn
    return self
  }

  var commandHandlers = {}
  self.getCommandHandlers = function () {
    return commandHandlers
  }

  self.string = function (strings) {
    options.string.push.apply(options.string, [].concat(strings))
    return self
  }

  self.default = function (key, value, defaultDescription) {
    if (typeof key === 'object') {
      Object.keys(key).forEach(function (k) {
        self.default(k, key[k])
      })
    } else {
      if (defaultDescription) options.defaultDescription[key] = defaultDescription
      if (typeof value === 'function') {
        if (!options.defaultDescription[key]) options.defaultDescription[key] = usage.functionDescription(value)
        value = value.call()
      }
      options.default[key] = value
    }
    return self
  }

  self.alias = function (x, y) {
    if (typeof x === 'object') {
      Object.keys(x).forEach(function (key) {
        self.alias(key, x[key])
      })
    } else {
      // perhaps 'x' is already an alias in another list?
      // if so we should append to x's list.
      var aliases = null
      Object.keys(options.alias).forEach(function (key) {
        if (~options.alias[key].indexOf(x)) aliases = options.alias[key]
      })

      if (aliases) { // x was an alias itself.
        aliases.push(y)
      } else { // x is a new alias key.
        options.alias[x] = (options.alias[x] || []).concat(y)
      }

      // wait! perhaps we've created two lists of aliases
      // that reference each other?
      if (options.alias[y]) {
        Array.prototype.push.apply((options.alias[x] || aliases), options.alias[y])
        delete options.alias[y]
      }
    }
    return self
  }

  self.count = function (counts) {
    options.count.push.apply(options.count, [].concat(counts))
    return self
  }

  var demanded = {}
  self.demand = self.required = self.require = function (keys, max, msg) {
    // you can optionally provide a 'max' key,
    // which will raise an exception if too many '_'
    // options are provided.
    if (typeof max !== 'number') {
      msg = max
      max = Infinity
    }

    if (typeof keys === 'number') {
      if (!demanded._) demanded._ = { count: 0, msg: null, max: max }
      demanded._.count = keys
      demanded._.msg = msg
    } else if (Array.isArray(keys)) {
      keys.forEach(function (key) {
        self.demand(key, msg)
      })
    } else {
      if (typeof msg === 'string') {
        demanded[keys] = { msg: msg }
      } else if (msg === true || typeof msg === 'undefined') {
        demanded[keys] = { msg: undefined }
      }
    }

    return self
  }
  self.getDemanded = function () {
    return demanded
  }

  self.requiresArg = function (requiresArgs) {
    options.requiresArg.push.apply(options.requiresArg, [].concat(requiresArgs))
    return self
  }

  self.implies = function (key, value) {
    validation.implies(key, value)
    return self
  }

  self.usage = function (msg, opts) {
    if (!opts && typeof msg === 'object') {
      opts = msg
      msg = null
    }

    usage.usage(msg)

    if (opts) self.options(opts)

    return self
  }

  self.epilogue = self.epilog = function (msg) {
    usage.epilog(msg)
    return self
  }

  self.fail = function (f) {
    usage.failFn(f)
    return self
  }

  self.check = function (f) {
    validation.check(f)
    return self
  }

  self.defaults = self.default

  self.describe = function (key, desc) {
    options.key[key] = true
    usage.describe(key, desc)
    return self
  }

  self.parse = function (args) {
    return parseArgs(args)
  }

  self.option = self.options = function (key, opt) {
    if (typeof key === 'object') {
      Object.keys(key).forEach(function (k) {
        self.options(k, key[k])
      })
    } else {
      assert(typeof opt === 'object', 'second argument to option must be an object')

      options.key[key] = true // track manually set keys.

      if (opt.alias) self.alias(key, opt.alias)

      var demand = opt.demand || opt.required || opt.require

      if (demand) {
        self.demand(key, demand)
      } if ('config' in opt) {
        self.config(key, opt.configParser)
      } if ('default' in opt) {
        self.default(key, opt.default)
      } if ('nargs' in opt) {
        self.nargs(key, opt.nargs)
      } if ('choices' in opt) {
        self.choices(key, opt.choices)
      } if ('group' in opt) {
        self.group(key, opt.group)
      } if (opt.boolean || opt.type === 'boolean') {
        self.boolean(key)
        if (opt.alias) self.boolean(opt.alias)
      } if (opt.array || opt.type === 'array') {
        self.array(key)
        if (opt.alias) self.array(opt.alias)
      } if (opt.string || opt.type === 'string') {
        self.string(key)
        if (opt.alias) self.string(opt.alias)
      } if (opt.count || opt.type === 'count') {
        self.count(key)
      } if (opt.defaultDescription) {
        options.defaultDescription[key] = opt.defaultDescription
      }

      var desc = opt.describe || opt.description || opt.desc
      if (desc) {
        self.describe(key, desc)
      }

      if (opt.requiresArg) {
        self.requiresArg(key)
      }
    }

    return self
  }
  self.getOptions = function () {
    return options
  }

  var groups = {}
  self.group = function (opts, groupName) {
    var seen = {}
    groups[groupName] = (groups[groupName] || []).concat(opts).filter(function (key) {
      if (seen[key]) return false
      return (seen[key] = true)
    })
    return self
  }
  self.getGroups = function () {
    return groups
  }

  // as long as options.envPrefix is not undefined,
  // parser will apply env vars matching prefix to argv
  self.env = function (prefix) {
    if (prefix === false) options.envPrefix = undefined
    else options.envPrefix = prefix || ''
    return self
  }

  self.wrap = function (cols) {
    usage.wrap(cols)
    return self
  }

  var strict = false
  self.strict = function () {
    strict = true
    return self
  }
  self.getStrict = function () {
    return strict
  }

  self.showHelp = function (level) {
    if (!self.parsed) parseArgs(processArgs) // run parser, if it has not already been executed.
    usage.showHelp(level)
    return self
  }

  var versionOpt = null
  self.version = function (ver, opt, msg) {
    versionOpt = opt || 'version'
    usage.version(ver)
    self.boolean(versionOpt)
    self.describe(versionOpt, msg || usage.deferY18nLookup('Show version number'))
    return self
  }

  var helpOpt = null
  self.addHelpOpt = function (opt, msg) {
    helpOpt = opt
    self.boolean(opt)
    self.describe(opt, msg || usage.deferY18nLookup('Show help'))
    return self
  }

  self.showHelpOnFail = function (enabled, message) {
    usage.showHelpOnFail(enabled, message)
    return self
  }

  var exitProcess = true
  self.exitProcess = function (enabled) {
    if (typeof enabled !== 'boolean') {
      enabled = true
    }
    exitProcess = enabled
    return self
  }
  self.getExitProcess = function () {
    return exitProcess
  }

  self.help = function () {
    if (arguments.length > 0) return self.addHelpOpt.apply(self, arguments)

    if (!self.parsed) parseArgs(processArgs) // run parser, if it has not already been executed.

    return usage.help()
  }

  var completionCommand = null
  self.completion = function (cmd, desc, fn) {
    // a function to execute when generating
    // completions can be provided as the second
    // or third argument to completion.
    if (typeof desc === 'function') {
      fn = desc
      desc = null
    }

    // register the completion command.
    completionCommand = cmd || 'completion'
    if (!desc && desc !== false) {
      desc = 'generate bash completion script'
    }
    self.command(completionCommand, desc)

    // a function can be provided
    if (fn) completion.registerFunction(fn)

    return self
  }

  self.showCompletionScript = function ($0) {
    $0 = $0 || self.$0
    console.log(completion.generateCompletionScript($0))
    return self
  }

  self.locale = function (locale) {
    if (arguments.length === 0) {
      guessLocale()
      return y18n.getLocale()
    }
    detectLocale = false
    y18n.setLocale(locale)
    return self
  }

  self.updateStrings = self.updateLocale = function (obj) {
    detectLocale = false
    y18n.updateLocale(obj)
    return self
  }

  var detectLocale = true
  self.detectLocale = function (detect) {
    detectLocale = detect
    return self
  }
  self.getDetectLocale = function () {
    return detectLocale
  }

  self.getUsageInstance = function () {
    return usage
  }

  self.getValidationInstance = function () {
    return validation
  }

  self.terminalWidth = function () {
    return require('window-size').width
  }

  Object.defineProperty(self, 'argv', {
    get: function () {
      var args = null

      try {
        args = parseArgs(processArgs)
      } catch (err) {
        usage.fail(err.message)
      }

      return args
    },
    enumerable: true
  })

  function parseArgs (args) {
    args = normalizeArgs(args)

    var parsed = Parser(args, options, y18n)
    var argv = parsed.argv
    var aliases = parsed.aliases

    argv.$0 = self.$0

    self.parsed = parsed

    guessLocale() // guess locale lazily, so that it can be turned off in chain.

    // while building up the argv object, there
    // are two passes through the parser. If completion
    // is being performed short-circuit on the first pass.
    if (completionCommand &&
      (process.argv.join(' ')).indexOf(completion.completionKey) !== -1 &&
      !argv[completion.completionKey]) {
      return argv
    }

    // if there's a handler associated with a
    // command defer processing to it.
    var handlerKeys = Object.keys(self.getCommandHandlers())
    for (var i = 0, command; (command = handlerKeys[i]) !== undefined; i++) {
      if (~argv._.indexOf(command)) {
        runCommand(command, self, argv)
        return self.argv
      }
    }

    // generate a completion script for adding to ~/.bashrc.
    if (completionCommand && ~argv._.indexOf(completionCommand) && !argv[completion.completionKey]) {
      self.showCompletionScript()
      if (exitProcess) {
        process.exit(0)
      }
    }

    // we must run completions first, a user might
    // want to complete the --help or --version option.
    if (completion.completionKey in argv) {
      // we allow for asynchronous completions,
      // e.g., loading in a list of commands from an API.
      completion.getCompletion(function (completions) {
        ;(completions || []).forEach(function (completion) {
          console.log(completion)
        })

        if (exitProcess) {
          process.exit(0)
        }
      })
      return
    }

    var helpOrVersion = false
    Object.keys(argv).forEach(function (key) {
      if (key === helpOpt && argv[key]) {
        helpOrVersion = true
        self.showHelp('log')
        if (exitProcess) {
          process.exit(0)
        }
      } else if (key === versionOpt && argv[key]) {
        helpOrVersion = true
        usage.showVersion()
        if (exitProcess) {
          process.exit(0)
        }
      }
    })

    // If the help or version options where used and exitProcess is false,
    // we won't run validations
    if (!helpOrVersion) {
      if (parsed.error) throw parsed.error

      // if we're executed via bash completion, don't
      // bother with validation.
      if (!argv[completion.completionKey]) {
        validation.nonOptionCount(argv)
        validation.missingArgumentValue(argv)
        validation.requiredArguments(argv)
        if (strict) validation.unknownArguments(argv, aliases)
        validation.customChecks(argv, aliases)
        validation.limitedChoices(argv)
        validation.implications(argv)
      }
    }

    setPlaceholderKeys(argv)

    return argv
  }

  function guessLocale () {
    if (!detectLocale) return

    try {
      var osLocale = require('os-locale')
      self.locale(osLocale.sync({ spawn: false }))
    } catch (err) {
      // if we explode looking up locale just noop
      // we'll keep using the default language 'en'.
    }
  }

  function runCommand (command, yargs, argv) {
    setPlaceholderKeys(argv)
    yargs.getCommandHandlers()[command](yargs.reset(), argv)
  }

  function setPlaceholderKeys (argv) {
    Object.keys(options.key).forEach(function (key) {
      // don't set placeholder keys for dot
      // notation options 'foo.bar'.
      if (~key.indexOf('.')) return
      if (typeof argv[key] === 'undefined') argv[key] = undefined
    })
  }

  function normalizeArgs (args) {
    if (typeof args === 'string') {
      return tokenizeArgString(args)
    }
    return args
  }

  singletonify(self)
  return self
}

// rebase an absolute path to a relative one with respect to a base directory
// exported for tests
exports.rebase = rebase
function rebase (base, dir) {
  return path.relative(base, dir)
}

/*  Hack an instance of Argv with process.argv into Argv
    so people can do
    require('yargs')(['--beeble=1','-z','zizzle']).argv
    to parse a list of args and
    require('yargs').argv
    to get a parsed version of process.argv.
*/
function singletonify (inst) {
  Object.keys(inst).forEach(function (key) {
    if (key === 'argv') {
      Argv.__defineGetter__(key, inst.__lookupGetter__(key))
    } else {
      Argv[key] = typeof inst[key] === 'function' ? inst[key].bind(inst) : inst[key]
    }
  })
}

}, function(modId) {var map = {"./lib/completion":1603008214504,"./lib/parser":1603008214505,"./lib/tokenize-arg-string":1603008214506,"./lib/usage":1603008214507,"./lib/validation":1603008214508}; return __REQUIRE__(map[modId], modId); })
__DEFINE__(1603008214504, function(require, module, exports) {
var fs = require('fs')
var path = require('path')

// add bash completions to your
//  yargs-powered applications.
module.exports = function (yargs, usage) {
  var self = {
    completionKey: 'get-yargs-completions'
  }

  // get a list of completion commands.
  self.getCompletion = function (done) {
    var completions = []
    var current = process.argv[process.argv.length - 1]
    var previous = process.argv.slice(process.argv.indexOf('--' + self.completionKey) + 1)
    var argv = yargs.parse(previous)

    // a custom completion function can be provided
    // to completion().
    if (completionFunction) {
      if (completionFunction.length < 3) {
        var result = completionFunction(current, argv)

        // promise based completion function.
        if (typeof result.then === 'function') {
          return result.then(function (list) {
            process.nextTick(function () { done(list) })
          }).catch(function (err) {
            process.nextTick(function () { throw err })
          })
        }

        // synchronous completion function.
        return done(result)
      } else {
        // asynchronous completion function
        return completionFunction(current, argv, function (completions) {
          done(completions)
        })
      }
    }

    var handlers = yargs.getCommandHandlers()
    for (var i = 0, ii = previous.length; i < ii; ++i) {
      if (handlers[previous[i]]) {
        return handlers[previous[i]](yargs.reset())
      }
    }

    if (!current.match(/^-/)) {
      usage.getCommands().forEach(function (command) {
        if (previous.indexOf(command[0]) === -1) {
          completions.push(command[0])
        }
      })
    }

    if (current.match(/^-/)) {
      Object.keys(yargs.getOptions().key).forEach(function (key) {
        completions.push('--' + key)
      })
    }

    done(completions)
  }

  // generate the completion script to add to your .bashrc.
  self.generateCompletionScript = function ($0) {
    var script = fs.readFileSync(
      path.resolve(__dirname, '../completion.sh.hbs'),
      'utf-8'
    )
    var name = path.basename($0)

    // add ./to applications not yet installed as bin.
    if ($0.match(/\.js$/)) $0 = './' + $0

    script = script.replace(/{{app_name}}/g, name)
    return script.replace(/{{app_path}}/g, $0)
  }

  // register a function to perform your own custom
  // completions., this function can be either
  // synchrnous or asynchronous.
  var completionFunction = null
  self.registerFunction = function (fn) {
    completionFunction = fn
  }

  return self
}

}, function(modId) { var map = {}; return __REQUIRE__(map[modId], modId); })
__DEFINE__(1603008214505, function(require, module, exports) {
// fancy-pants parsing of argv, originally forked
// from minimist: https://www.npmjs.com/package/minimist
var camelCase = require('camelcase')
var path = require('path')

function increment (orig) {
  return orig !== undefined ? orig + 1 : 0
}

module.exports = function (args, opts, y18n) {
  if (!opts) opts = {}

  var __ = y18n.__
  var error = null
  var flags = { arrays: {}, bools: {}, strings: {}, counts: {}, normalize: {}, configs: {}, defaulted: {} }

  ;[].concat(opts['array']).filter(Boolean).forEach(function (key) {
    flags.arrays[key] = true
  })

  ;[].concat(opts['boolean']).filter(Boolean).forEach(function (key) {
    flags.bools[key] = true
  })

  ;[].concat(opts.string).filter(Boolean).forEach(function (key) {
    flags.strings[key] = true
  })

  ;[].concat(opts.count).filter(Boolean).forEach(function (key) {
    flags.counts[key] = true
  })

  ;[].concat(opts.normalize).filter(Boolean).forEach(function (key) {
    flags.normalize[key] = true
  })

  Object.keys(opts.config).forEach(function (k) {
    flags.configs[k] = opts.config[k]
  })

  var aliases = {}
  var newAliases = {}

  extendAliases(opts.key)
  extendAliases(opts.alias)
  extendAliases(opts.default)

  var defaults = opts['default'] || {}
  Object.keys(defaults).forEach(function (key) {
    if (/-/.test(key) && !opts.alias[key]) {
      aliases[key] = aliases[key] || []
    }
    (aliases[key] || []).forEach(function (alias) {
      defaults[alias] = defaults[key]
    })
  })

  var argv = { _: [] }

  Object.keys(flags.bools).forEach(function (key) {
    setArg(key, !(key in defaults) ? false : defaults[key])
    setDefaulted(key)
  })

  var notFlags = []
  if (args.indexOf('--') !== -1) {
    notFlags = args.slice(args.indexOf('--') + 1)
    args = args.slice(0, args.indexOf('--'))
  }

  for (var i = 0; i < args.length; i++) {
    var arg = args[i]
    var broken
    var key
    var letters
    var m
    var next
    var value

    // -- seperated by =
    if (arg.match(/^--.+=/)) {
      // Using [\s\S] instead of . because js doesn't support the
      // 'dotall' regex modifier. See:
      // http://stackoverflow.com/a/1068308/13216
      m = arg.match(/^--([^=]+)=([\s\S]*)$/)

      // nargs format = '--f=monkey washing cat'
      if (checkAllAliases(m[1], opts.narg)) {
        args.splice(i + 1, m[1], m[2])
        i = eatNargs(i, m[1], args)
      // arrays format = '--f=a b c'
      } else if (checkAllAliases(m[1], flags.arrays) && args.length > i + 1) {
        args.splice(i + 1, m[1], m[2])
        i = eatArray(i, m[1], args)
      } else {
        setArg(m[1], m[2])
      }
    } else if (arg.match(/^--no-.+/)) {
      key = arg.match(/^--no-(.+)/)[1]
      setArg(key, false)

    // -- seperated by space.
    } else if (arg.match(/^--.+/)) {
      key = arg.match(/^--(.+)/)[1]

      // nargs format = '--foo a b c'
      if (checkAllAliases(key, opts.narg)) {
        i = eatNargs(i, key, args)
      // array format = '--foo a b c'
      } else if (checkAllAliases(key, flags.arrays) && args.length > i + 1) {
        i = eatArray(i, key, args)
      } else {
        next = args[i + 1]

        if (next !== undefined && !next.match(/^-/) &&
          !checkAllAliases(key, flags.bools) &&
          !checkAllAliases(key, flags.counts)) {
          setArg(key, next)
          i++
        } else if (/^(true|false)$/.test(next)) {
          setArg(key, next)
          i++
        } else {
          setArg(key, defaultForType(guessType(key, flags)))
        }
      }

    // dot-notation flag seperated by '='.
    } else if (arg.match(/^-.\..+=/)) {
      m = arg.match(/^-([^=]+)=([\s\S]*)$/)
      setArg(m[1], m[2])

    // dot-notation flag seperated by space.
    } else if (arg.match(/^-.\..+/)) {
      next = args[i + 1]
      key = arg.match(/^-(.\..+)/)[1]

      if (next !== undefined && !next.match(/^-/) &&
        !checkAllAliases(key, flags.bools) &&
        !checkAllAliases(key, flags.counts)) {
        setArg(key, next)
        i++
      } else {
        setArg(key, defaultForType(guessType(key, flags)))
      }
    } else if (arg.match(/^-[^-]+/)) {
      letters = arg.slice(1, -1).split('')
      broken = false

      for (var j = 0; j < letters.length; j++) {
        next = arg.slice(j + 2)

        if (letters[j + 1] && letters[j + 1] === '=') {
          value = arg.slice(j + 3)
          key = letters[j]

          // nargs format = '-f=monkey washing cat'
          if (checkAllAliases(letters[j], opts.narg)) {
            args.splice(i + 1, 0, value)
            i = eatNargs(i, key, args)
          // array format = '-f=a b c'
          } else if (checkAllAliases(key, flags.arrays) && args.length > i + 1) {
            args.splice(i + 1, 0, value)
            i = eatArray(i, key, args)
          } else {
            setArg(key, value)
          }

          broken = true
          break
        }

        if (next === '-') {
          setArg(letters[j], next)
          continue
        }

        if (/[A-Za-z]/.test(letters[j]) &&
          /-?\d+(\.\d*)?(e-?\d+)?$/.test(next)) {
          setArg(letters[j], next)
          broken = true
          break
        }

        if (letters[j + 1] && letters[j + 1].match(/\W/)) {
          setArg(letters[j], arg.slice(j + 2))
          broken = true
          break
        } else {
          setArg(letters[j], defaultForType(guessType(letters[j], flags)))
        }
      }

      key = arg.slice(-1)[0]

      if (!broken && key !== '-') {
        // nargs format = '-f a b c'
        if (checkAllAliases(key, opts.narg)) {
          i = eatNargs(i, key, args)
        // array format = '-f a b c'
        } else if (checkAllAliases(key, flags.arrays) && args.length > i + 1) {
          i = eatArray(i, key, args)
        } else {
          if (args[i + 1] && !/^(-|--)[^-]/.test(args[i + 1]) &&
            !checkAllAliases(key, flags.bools) &&
            !checkAllAliases(key, flags.counts)) {
            setArg(key, args[i + 1])
            i++
          } else if (args[i + 1] && /true|false/.test(args[i + 1])) {
            setArg(key, args[i + 1])
            i++
          } else {
            setArg(key, defaultForType(guessType(key, flags)))
          }
        }
      }
    } else {
      argv._.push(
        flags.strings['_'] || !isNumber(arg) ? arg : Number(arg)
      )
    }
  }

  // order of precedence:
  // 1. command line arg
  // 2. value from config file
  // 3. value from env var
  // 4. configured default value
  applyEnvVars(opts, argv, true) // special case: check env vars that point to config file
  setConfig(argv)
  applyEnvVars(opts, argv, false)
  applyDefaultsAndAliases(argv, aliases, defaults)

  Object.keys(flags.counts).forEach(function (key) {
    setArg(key, defaults[key])
  })

  notFlags.forEach(function (key) {
    argv._.push(key)
  })

  // how many arguments should we consume, based
  // on the nargs option?
  function eatNargs (i, key, args) {
    var toEat = checkAllAliases(key, opts.narg)

    if (args.length - (i + 1) < toEat) error = Error(__('Not enough arguments following: %s', key))

    for (var ii = i + 1; ii < (toEat + i + 1); ii++) {
      setArg(key, args[ii])
    }

    return (i + toEat)
  }

  // if an option is an array, eat all non-hyphenated arguments
  // following it... YUM!
  // e.g., --foo apple banana cat becomes ["apple", "banana", "cat"]
  function eatArray (i, key, args) {
    for (var ii = i + 1; ii < args.length; ii++) {
      if (/^-/.test(args[ii])) break
      i = ii
      setArg(key, args[ii])
    }

    return i
  }

  function setArg (key, val) {
    unsetDefaulted(key)

    // handle parsing boolean arguments --foo=true --bar false.
    if (checkAllAliases(key, flags.bools) || checkAllAliases(key, flags.counts)) {
      if (typeof val === 'string') val = val === 'true'
    }

    if (/-/.test(key) && !(aliases[key] && aliases[key].length)) {
      var c = camelCase(key)
      aliases[key] = [c]
      newAliases[c] = true
    }

    var value = !checkAllAliases(key, flags.strings) && isNumber(val) ? Number(val) : val

    if (checkAllAliases(key, flags.counts)) {
      value = increment
    }

    var splitKey = key.split('.')
    setKey(argv, splitKey, value)

    // alias references an inner-value within
    // a dot-notation object. see #279.
    if (~key.indexOf('.') && aliases[key]) {
      aliases[key].forEach(function (x) {
        x = x.split('.')
        setKey(argv, x, value)
      })
    }

    ;(aliases[splitKey[0]] || []).forEach(function (x) {
      x = x.split('.')

      // handle populating dot notation for both
      // the key and its aliases.
      if (splitKey.length > 1) {
        var a = [].concat(splitKey)
        a.shift() // nuke the old key.
        x = x.concat(a)
      }

      setKey(argv, x, value)
    })

    var keys = [key].concat(aliases[key] || [])
    for (var i = 0, l = keys.length; i < l; i++) {
      if (flags.normalize[keys[i]]) {
        keys.forEach(function (key) {
          argv.__defineSetter__(key, function (v) {
            val = path.normalize(v)
          })

          argv.__defineGetter__(key, function () {
            return typeof val === 'string' ? path.normalize(val) : val
          })
        })
        break
      }
    }
  }

  // set args from config.json file, this should be
  // applied last so that defaults can be applied.
  function setConfig (argv) {
    var configLookup = {}

    // expand defaults/aliases, in-case any happen to reference
    // the config.json file.
    applyDefaultsAndAliases(configLookup, aliases, defaults)

    Object.keys(flags.configs).forEach(function (configKey) {
      var configPath = argv[configKey] || configLookup[configKey]
      if (configPath) {
        try {
          var config = null
          var resolvedConfigPath = path.resolve(process.cwd(), configPath)

          if (typeof flags.configs[configKey] === 'function') {
            try {
              config = flags.configs[configKey](resolvedConfigPath)
            } catch (e) {
              config = e
            }
            if (config instanceof Error) {
              error = config
              return
            }
          } else {
            config = require(resolvedConfigPath)
          }

          Object.keys(config).forEach(function (key) {
            // setting arguments via CLI takes precedence over
            // values within the config file.
            if (argv[key] === undefined || (flags.defaulted[key])) {
              delete argv[key]
              setArg(key, config[key])
            }
          })
        } catch (ex) {
          if (argv[configKey]) error = Error(__('Invalid JSON config file: %s', configPath))
        }
      }
    })
  }

  function applyEnvVars (opts, argv, configOnly) {
    if (typeof opts.envPrefix === 'undefined') return

    var prefix = typeof opts.envPrefix === 'string' ? opts.envPrefix : ''
    Object.keys(process.env).forEach(function (envVar) {
      if (prefix === '' || envVar.lastIndexOf(prefix, 0) === 0) {
        var key = camelCase(envVar.substring(prefix.length))
        if (((configOnly && flags.configs[key]) || !configOnly) && (!(key in argv) || flags.defaulted[key])) {
          setArg(key, process.env[envVar])
        }
      }
    })
  }

  function applyDefaultsAndAliases (obj, aliases, defaults) {
    Object.keys(defaults).forEach(function (key) {
      if (!hasKey(obj, key.split('.'))) {
        setKey(obj, key.split('.'), defaults[key])

        ;(aliases[key] || []).forEach(function (x) {
          if (hasKey(obj, x.split('.'))) return
          setKey(obj, x.split('.'), defaults[key])
        })
      }
    })
  }

  function hasKey (obj, keys) {
    var o = obj
    keys.slice(0, -1).forEach(function (key) {
      o = (o[key] || {})
    })

    var key = keys[keys.length - 1]

    if (typeof o !== 'object') return false
    else return key in o
  }

  function setKey (obj, keys, value) {
    var o = obj
    keys.slice(0, -1).forEach(function (key) {
      if (o[key] === undefined) o[key] = {}
      o = o[key]
    })

    var key = keys[keys.length - 1]
    if (value === increment) {
      o[key] = increment(o[key])
    } else if (o[key] === undefined && checkAllAliases(key, flags.arrays)) {
      o[key] = Array.isArray(value) ? value : [value]
    } else if (o[key] === undefined || typeof o[key] === 'boolean') {
      o[key] = value
    } else if (Array.isArray(o[key])) {
      o[key].push(value)
    } else {
      o[key] = [ o[key], value ]
    }
  }

  // extend the aliases list with inferred aliases.
  function extendAliases (obj) {
    Object.keys(obj || {}).forEach(function (key) {
      // short-circuit if we've already added a key
      // to the aliases array, for example it might
      // exist in both 'opts.default' and 'opts.key'.
      if (aliases[key]) return

      aliases[key] = [].concat(opts.alias[key] || [])
      // For "--option-name", also set argv.optionName
      aliases[key].concat(key).forEach(function (x) {
        if (/-/.test(x)) {
          var c = camelCase(x)
          aliases[key].push(c)
          newAliases[c] = true
        }
      })
      aliases[key].forEach(function (x) {
        aliases[x] = [key].concat(aliases[key].filter(function (y) {
          return x !== y
        }))
      })
    })
  }

  // check if a flag is set for any of a key's aliases.
  function checkAllAliases (key, flag) {
    var isSet = false
    var toCheck = [].concat(aliases[key] || [], key)

    toCheck.forEach(function (key) {
      if (flag[key]) isSet = flag[key]
    })

    return isSet
  }

  function setDefaulted (key) {
    [].concat(aliases[key] || [], key).forEach(function (k) {
      flags.defaulted[k] = true
    })
  }

  function unsetDefaulted (key) {
    [].concat(aliases[key] || [], key).forEach(function (k) {
      delete flags.defaulted[k]
    })
  }

  // return a default value, given the type of a flag.,
  // e.g., key of type 'string' will default to '', rather than 'true'.
  function defaultForType (type) {
    var def = {
      boolean: true,
      string: '',
      array: []
    }

    return def[type]
  }

  // given a flag, enforce a default type.
  function guessType (key, flags) {
    var type = 'boolean'

    if (flags.strings && flags.strings[key]) type = 'string'
    else if (flags.arrays && flags.arrays[key]) type = 'array'

    return type
  }

  function isNumber (x) {
    if (typeof x === 'number') return true
    if (/^0x[0-9a-f]+$/i.test(x)) return true
    return /^[-+]?(?:\d+(?:\.\d*)?|\.\d+)(e[-+]?\d+)?$/.test(x)
  }

  return {
    argv: argv,
    aliases: aliases,
    error: error,
    newAliases: newAliases
  }
}

}, function(modId) { var map = {}; return __REQUIRE__(map[modId], modId); })
__DEFINE__(1603008214506, function(require, module, exports) {
// take an un-split argv string and tokenize it.
module.exports = function (argString) {
  var i = 0
  var c = null
  var opening = null
  var args = []

  for (var ii = 0; ii < argString.length; ii++) {
    c = argString.charAt(ii)

    // split on spaces unless we're in quotes.
    if (c === ' ' && !opening) {
      i++
      continue
    }

    // don't split the string if we're in matching
    // opening or closing single and double quotes.
    if (c === opening) {
      opening = null
      continue
    } else if ((c === "'" || c === '"') && !opening) {
      opening = c
      continue
    }

    if (!args[i]) args[i] = ''
    args[i] += c
  }

  return args
}

}, function(modId) { var map = {}; return __REQUIRE__(map[modId], modId); })
__DEFINE__(1603008214507, function(require, module, exports) {
// this file handles outputting usage instructions,
// failures, etc. keeps logging in one place.
var cliui = require('cliui')
var decamelize = require('decamelize')
var stringWidth = require('string-width')
var wsize = require('window-size')

module.exports = function (yargs, y18n) {
  var __ = y18n.__
  var self = {}

  // methods for ouputting/building failure message.
  var fails = []
  self.failFn = function (f) {
    fails.push(f)
  }

  var failMessage = null
  var showHelpOnFail = true
  self.showHelpOnFail = function (enabled, message) {
    if (typeof enabled === 'string') {
      message = enabled
      enabled = true
    } else if (typeof enabled === 'undefined') {
      enabled = true
    }
    failMessage = message
    showHelpOnFail = enabled
    return self
  }

  var failureOutput = false
  self.fail = function (msg) {
    if (fails.length) {
      fails.forEach(function (f) {
        f(msg)
      })
    } else {
      // don't output failure message more than once
      if (!failureOutput) {
        failureOutput = true
        if (showHelpOnFail) yargs.showHelp('error')
        if (msg) console.error(msg)
        if (failMessage) {
          if (msg) console.error('')
          console.error(failMessage)
        }
      }
      if (yargs.getExitProcess()) {
        process.exit(1)
      } else {
        throw new Error(msg)
      }
    }
  }

  // methods for ouputting/building help (usage) message.
  var usage
  self.usage = function (msg) {
    usage = msg
  }

  var examples = []
  self.example = function (cmd, description) {
    examples.push([cmd, description || ''])
  }

  var commands = []
  self.command = function (cmd, description) {
    commands.push([cmd, description || ''])
  }
  self.getCommands = function () {
    return commands
  }

  var descriptions = {}
  self.describe = function (key, desc) {
    if (typeof key === 'object') {
      Object.keys(key).forEach(function (k) {
        self.describe(k, key[k])
      })
    } else {
      descriptions[key] = desc
    }
  }
  self.getDescriptions = function () {
    return descriptions
  }

  var epilog
  self.epilog = function (msg) {
    epilog = msg
  }

  var wrap = windowWidth()
  self.wrap = function (cols) {
    wrap = cols
  }

  var deferY18nLookupPrefix = '__yargsString__:'
  self.deferY18nLookup = function (str) {
    return deferY18nLookupPrefix + str
  }

  var defaultGroup = 'Options:'
  self.help = function () {
    normalizeAliases()

    var demanded = yargs.getDemanded()
    var groups = yargs.getGroups()
    var options = yargs.getOptions()
    var keys = Object.keys(
      Object.keys(descriptions)
      .concat(Object.keys(demanded))
      .concat(Object.keys(options.default))
      .reduce(function (acc, key) {
        if (key !== '_') acc[key] = true
        return acc
      }, {})
    )
    var ui = cliui({
      width: wrap,
      wrap: !!wrap
    })

    // the usage string.
    if (usage) {
      var u = usage.replace(/\$0/g, yargs.$0)
      ui.div(u + '\n')
    }

    // your application's commands, i.e., non-option
    // arguments populated in '_'.
    if (commands.length) {
      ui.div(__('Commands:'))

      commands.forEach(function (command) {
        ui.div(
          {text: command[0], padding: [0, 2, 0, 2], width: maxWidth(commands) + 4},
          {text: command[1]}
        )
      })

      ui.div()
    }

    // perform some cleanup on the keys array, making it
    // only include top-level keys not their aliases.
    var aliasKeys = (Object.keys(options.alias) || [])
      .concat(Object.keys(yargs.parsed.newAliases) || [])

    keys = keys.filter(function (key) {
      return !yargs.parsed.newAliases[key] && aliasKeys.every(function (alias) {
        return (options.alias[alias] || []).indexOf(key) === -1
      })
    })

    // populate 'Options:' group with any keys that have not
    // explicitly had a group set.
    if (!groups[defaultGroup]) groups[defaultGroup] = []
    addUngroupedKeys(keys, options.alias, groups)

    // display 'Options:' table along with any custom tables:
    Object.keys(groups).forEach(function (groupName) {
      if (!groups[groupName].length) return

      ui.div(__(groupName))

      // if we've grouped the key 'f', but 'f' aliases 'foobar',
      // normalizedKeys should contain only 'foobar'.
      var normalizedKeys = groups[groupName].map(function (key) {
        if (~aliasKeys.indexOf(key)) return key
        for (var i = 0, aliasKey; (aliasKey = aliasKeys[i]) !== undefined; i++) {
          if (~(options.alias[aliasKey] || []).indexOf(key)) return aliasKey
        }
        return key
      })

      // actually generate the switches string --foo, -f, --bar.
      var switches = normalizedKeys.reduce(function (acc, key) {
        acc[key] = [ key ].concat(options.alias[key] || [])
          .map(function (sw) {
            return (sw.length > 1 ? '--' : '-') + sw
          })
          .join(', ')

        return acc
      }, {})

      normalizedKeys.forEach(function (key) {
        var kswitch = switches[key]
        var desc = descriptions[key] || ''
        var type = null

        if (~desc.lastIndexOf(deferY18nLookupPrefix)) desc = __(desc.substring(deferY18nLookupPrefix.length))

        if (~options.boolean.indexOf(key)) type = '[' + __('boolean') + ']'
        if (~options.count.indexOf(key)) type = '[' + __('count') + ']'
        if (~options.string.indexOf(key)) type = '[' + __('string') + ']'
        if (~options.normalize.indexOf(key)) type = '[' + __('string') + ']'
        if (~options.array.indexOf(key)) type = '[' + __('array') + ']'

        var extra = [
          type,
          demanded[key] ? '[' + __('required') + ']' : null,
          options.choices && options.choices[key] ? '[' + __('choices:') + ' ' +
            self.stringifiedValues(options.choices[key]) + ']' : null,
          defaultString(options.default[key], options.defaultDescription[key])
        ].filter(Boolean).join(' ')

        ui.span(
          {text: kswitch, padding: [0, 2, 0, 2], width: maxWidth(switches) + 4},
          desc
        )

        if (extra) ui.div({text: extra, padding: [0, 0, 0, 2], align: 'right'})
        else ui.div()
      })

      ui.div()
    })

    // describe some common use-cases for your application.
    if (examples.length) {
      ui.div(__('Examples:'))

      examples.forEach(function (example) {
        example[0] = example[0].replace(/\$0/g, yargs.$0)
      })

      examples.forEach(function (example) {
        ui.div(
          {text: example[0], padding: [0, 2, 0, 2], width: maxWidth(examples) + 4},
          example[1]
        )
      })

      ui.div()
    }

    // the usage string.
    if (epilog) {
      var e = epilog.replace(/\$0/g, yargs.$0)
      ui.div(e + '\n')
    }

    return ui.toString()
  }

  // return the maximum width of a string
  // in the left-hand column of a table.
  function maxWidth (table) {
    var width = 0

    // table might be of the form [leftColumn],
    // or {key: leftColumn}}
    if (!Array.isArray(table)) {
      table = Object.keys(table).map(function (key) {
        return [table[key]]
      })
    }

    table.forEach(function (v) {
      width = Math.max(stringWidth(v[0]), width)
    })

    // if we've enabled 'wrap' we should limit
    // the max-width of the left-column.
    if (wrap) width = Math.min(width, parseInt(wrap * 0.5, 10))

    return width
  }

  // make sure any options set for aliases,
  // are copied to the keys being aliased.
  function normalizeAliases () {
    var demanded = yargs.getDemanded()
    var options = yargs.getOptions()

    ;(Object.keys(options.alias) || []).forEach(function (key) {
      options.alias[key].forEach(function (alias) {
        // copy descriptions.
        if (descriptions[alias]) self.describe(key, descriptions[alias])
        // copy demanded.
        if (demanded[alias]) yargs.demand(key, demanded[alias].msg)
        // type messages.
        if (~options.boolean.indexOf(alias)) yargs.boolean(key)
        if (~options.count.indexOf(alias)) yargs.count(key)
        if (~options.string.indexOf(alias)) yargs.string(key)
        if (~options.normalize.indexOf(alias)) yargs.normalize(key)
        if (~options.array.indexOf(alias)) yargs.array(key)
      })
    })
  }

  // given a set of keys, place any keys that are
  // ungrouped under the 'Options:' grouping.
  function addUngroupedKeys (keys, aliases, groups) {
    var groupedKeys = []
    var toCheck = null
    Object.keys(groups).forEach(function (group) {
      groupedKeys = groupedKeys.concat(groups[group])
    })

    keys.forEach(function (key) {
      toCheck = [key].concat(aliases[key])
      if (!toCheck.some(function (k) {
        return groupedKeys.indexOf(k) !== -1
      })) {
        groups[defaultGroup].push(key)
      }
    })
    return groupedKeys
  }

  self.showHelp = function (level) {
    level = level || 'error'
    console[level](self.help())
  }

  self.functionDescription = function (fn) {
    var description = fn.name ? decamelize(fn.name, '-') : __('generated-value')
    return ['(', description, ')'].join('')
  }

  self.stringifiedValues = function (values, separator) {
    var string = ''
    var sep = separator || ', '
    var array = [].concat(values)

    if (!values || !array.length) return string

    array.forEach(function (value) {
      if (string.length) string += sep
      string += JSON.stringify(value)
    })

    return string
  }

  // format the default-value-string displayed in
  // the right-hand column.
  function defaultString (value, defaultDescription) {
    var string = '[' + __('default:') + ' '

    if (value === undefined && !defaultDescription) return null

    if (defaultDescription) {
      string += defaultDescription
    } else {
      switch (typeof value) {
        case 'string':
          string += JSON.stringify(value)
          break
        case 'object':
          string += JSON.stringify(value)
          break
        default:
          string += value
      }
    }

    return string + ']'
  }

  // guess the width of the console window, max-width 80.
  function windowWidth () {
    return wsize.width ? Math.min(80, wsize.width) : null
  }

  // logic for displaying application version.
  var version = null
  self.version = function (ver, opt, msg) {
    version = ver
  }

  self.showVersion = function () {
    if (typeof version === 'function') console.log(version())
    else console.log(version)
  }

  return self
}

}, function(modId) { var map = {}; return __REQUIRE__(map[modId], modId); })
__DEFINE__(1603008214508, function(require, module, exports) {
// validation-type-stuff, missing params,
// bad implications, custom checks.
module.exports = function (yargs, usage, y18n) {
  var __ = y18n.__
  var __n = y18n.__n
  var self = {}

  // validate appropriate # of non-option
  // arguments were provided, i.e., '_'.
  self.nonOptionCount = function (argv) {
    var demanded = yargs.getDemanded()
    var _s = argv._.length

    if (demanded._ && (_s < demanded._.count || _s > demanded._.max)) {
      if (demanded._.msg !== undefined) {
        usage.fail(demanded._.msg)
      } else if (_s < demanded._.count) {
        usage.fail(
          __('Not enough non-option arguments: got %s, need at least %s', argv._.length, demanded._.count)
        )
      } else {
        usage.fail(
          __('Too many non-option arguments: got %s, maximum of %s', argv._.length, demanded._.max)
        )
      }
    }
  }

  // make sure that any args that require an
  // value (--foo=bar), have a value.
  self.missingArgumentValue = function (argv) {
    var defaultValues = [true, false, '']
    var options = yargs.getOptions()

    if (options.requiresArg.length > 0) {
      var missingRequiredArgs = []

      options.requiresArg.forEach(function (key) {
        var value = argv[key]

        // if a value is explicitly requested,
        // flag argument as missing if it does not
        // look like foo=bar was entered.
        if (~defaultValues.indexOf(value) ||
          (Array.isArray(value) && !value.length)) {
          missingRequiredArgs.push(key)
        }
      })

      if (missingRequiredArgs.length > 0) {
        usage.fail(__n(
          'Missing argument value: %s',
          'Missing argument values: %s',
          missingRequiredArgs.length,
          missingRequiredArgs.join(', ')
        ))
      }
    }
  }

  // make sure all the required arguments are present.
  self.requiredArguments = function (argv) {
    var demanded = yargs.getDemanded()
    var missing = null

    Object.keys(demanded).forEach(function (key) {
      if (!argv.hasOwnProperty(key)) {
        missing = missing || {}
        missing[key] = demanded[key]
      }
    })

    if (missing) {
      var customMsgs = []
      Object.keys(missing).forEach(function (key) {
        var msg = missing[key].msg
        if (msg && customMsgs.indexOf(msg) < 0) {
          customMsgs.push(msg)
        }
      })

      var customMsg = customMsgs.length ? '\n' + customMsgs.join('\n') : ''

      usage.fail(__n(
        'Missing required argument: %s',
        'Missing required arguments: %s',
        Object.keys(missing).length,
        Object.keys(missing).join(', ') + customMsg
      ))
    }
  }

  // check for unknown arguments (strict-mode).
  self.unknownArguments = function (argv, aliases) {
    var aliasLookup = {}
    var descriptions = usage.getDescriptions()
    var demanded = yargs.getDemanded()
    var unknown = []

    Object.keys(aliases).forEach(function (key) {
      aliases[key].forEach(function (alias) {
        aliasLookup[alias] = key
      })
    })

    Object.keys(argv).forEach(function (key) {
      if (key !== '$0' && key !== '_' &&
        !descriptions.hasOwnProperty(key) &&
        !demanded.hasOwnProperty(key) &&
        !aliasLookup.hasOwnProperty(key)) {
        unknown.push(key)
      }
    })

    if (unknown.length > 0) {
      usage.fail(__n(
        'Unknown argument: %s',
        'Unknown arguments: %s',
        unknown.length,
        unknown.join(', ')
      ))
    }
  }

  // validate arguments limited to enumerated choices
  self.limitedChoices = function (argv) {
    var options = yargs.getOptions()
    var invalid = {}

    if (!Object.keys(options.choices).length) return

    Object.keys(argv).forEach(function (key) {
      if (key !== '$0' && key !== '_' &&
        options.choices.hasOwnProperty(key)) {
        [].concat(argv[key]).forEach(function (value) {
          // TODO case-insensitive configurability
          if (options.choices[key].indexOf(value) === -1) {
            invalid[key] = (invalid[key] || []).concat(value)
          }
        })
      }
    })

    var invalidKeys = Object.keys(invalid)

    if (!invalidKeys.length) return

    var msg = __('Invalid values:')
    invalidKeys.forEach(function (key) {
      msg += '\n  ' + __(
        'Argument: %s, Given: %s, Choices: %s',
        key,
        usage.stringifiedValues(invalid[key]),
        usage.stringifiedValues(options.choices[key])
      )
    })
    usage.fail(msg)
  }

  // custom checks, added using the `check` option on yargs.
  var checks = []
  self.check = function (f) {
    checks.push(f)
  }

  self.customChecks = function (argv, aliases) {
    checks.forEach(function (f) {
      try {
        var result = f(argv, aliases)
        if (!result) {
          usage.fail(__('Argument check failed: %s', f.toString()))
        } else if (typeof result === 'string') {
          usage.fail(result)
        }
      } catch (err) {
        usage.fail(err.message ? err.message : err)
      }
    })
  }

  // check implications, argument foo implies => argument bar.
  var implied = {}
  self.implies = function (key, value) {
    if (typeof key === 'object') {
      Object.keys(key).forEach(function (k) {
        self.implies(k, key[k])
      })
    } else {
      implied[key] = value
    }
  }
  self.getImplied = function () {
    return implied
  }

  self.implications = function (argv) {
    var implyFail = []

    Object.keys(implied).forEach(function (key) {
      var num
      var origKey = key
      var value = implied[key]

      // convert string '1' to number 1
      num = Number(key)
      key = isNaN(num) ? key : num

      if (typeof key === 'number') {
        // check length of argv._
        key = argv._.length >= key
      } else if (key.match(/^--no-.+/)) {
        // check if key doesn't exist
        key = key.match(/^--no-(.+)/)[1]
        key = !argv[key]
      } else {
        // check if key exists
        key = argv[key]
      }

      num = Number(value)
      value = isNaN(num) ? value : num

      if (typeof value === 'number') {
        value = argv._.length >= value
      } else if (value.match(/^--no-.+/)) {
        value = value.match(/^--no-(.+)/)[1]
        value = !argv[value]
      } else {
        value = argv[value]
      }

      if (key && !value) {
        implyFail.push(origKey)
      }
    })

    if (implyFail.length) {
      var msg = __('Implications failed:') + '\n'

      implyFail.forEach(function (key) {
        msg += ('  ' + key + ' -> ' + implied[key])
      })

      usage.fail(msg)
    }
  }

  return self
}

}, function(modId) { var map = {}; return __REQUIRE__(map[modId], modId); })
return __REQUIRE__(1603008214503);
})()
//# sourceMappingURL=index.js.map
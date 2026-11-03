'use strict';

const { createRequire } = require('module');

const requireNative = createRequire(__filename);
const impl = requireNative('minimatch-native');

function globPartFromMatcher(matcher) {
  const globPattern = matcher.pattern;
  return {
    _glob: globPattern,
    [Symbol.match](str) {
      return matcher.test(str) ? [str] : null;
    },
  };
}

function transformSetRow(row) {
  return row.map((cell) => {
    if (typeof cell === 'string') {
      return cell;
    }
    if (cell === impl.GLOBSTAR) {
      return impl.GLOBSTAR;
    }
    if (cell && typeof cell.pattern === 'string' && typeof cell.test === 'function') {
      return globPartFromMatcher(cell);
    }
    return cell;
  });
}

class CompatMinimatch extends impl.Minimatch {
  constructor(pattern, options) {
    super(pattern, options);
    this._nativeSet = this.set;
    this.set = this._nativeSet.map(transformSetRow);
  }

  match(target, partial) {
    const globSet = this.set;
    this.set = this._nativeSet;
    try {
      return super.match(target, partial);
    } finally {
      this.set = globSet;
    }
  }

  makeRe() {
    return makeRe(this.pattern, this.options);
  }
}

function makeRe(pattern, options) {
  const mm = new CompatMinimatch(pattern, options || {});
  return {
    test(path) {
      return mm.match(path);
    },
  };
}

function minimatch(target, pattern, options) {
  return impl.minimatch(target, pattern, options);
}

Object.assign(minimatch, impl);
minimatch.minimatch = impl.minimatch;
minimatch.Minimatch = CompatMinimatch;
minimatch.makeRe = makeRe;
minimatch.GLOBSTAR = impl.GLOBSTAR;
minimatch.default = minimatch;

module.exports = minimatch;

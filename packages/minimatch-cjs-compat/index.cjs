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

function CompatMinimatch(pattern, options) {
  if (!(this instanceof CompatMinimatch)) {
    return new CompatMinimatch(pattern, options);
  }
  const inner = new impl.Minimatch(pattern, options);
  this._inner = inner;
  this.options = inner.options;
  this.negate = inner.negate;
  this.globSet = inner.globSet;
  this.set = inner.set.map(transformSetRow);
}

CompatMinimatch.prototype.match = function match(target, partial) {
  return this._inner.match(target, partial);
};

function minimatch(target, pattern, options) {
  return impl.minimatch(target, pattern, options);
}

Object.assign(minimatch, impl);
minimatch.minimatch = impl.minimatch;
minimatch.Minimatch = CompatMinimatch;
minimatch.GLOBSTAR = impl.GLOBSTAR;
minimatch.default = minimatch;

module.exports = minimatch;

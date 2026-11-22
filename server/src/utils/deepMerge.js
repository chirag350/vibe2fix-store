const FORBIDDEN_KEYS = new Set(['__proto__', 'constructor', 'prototype']);

function isObject(item) {
  return item && typeof item === 'object' && !Array.isArray(item);
}

function deepMerge(target, source) {
  if (!isObject(target) || !isObject(source)) {
    return source;
  }

  for (const key of Object.keys(source)) {
    if (FORBIDDEN_KEYS.has(key)) continue; // never allow prototype pollution
    if (isObject(source[key])) {
      if (!isObject(target[key]) || !Object.prototype.hasOwnProperty.call(target, key)) {
        target[key] = Object.create(null);
      }
      deepMerge(target[key], source[key]);
    } else {
      target[key] = source[key];
    }
  }

  return target;
}

module.exports = deepMerge;

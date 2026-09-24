const traverse = require("@babel/traverse").default;
const t = require("@babel/types");

function buildLocalCache(chain) {
  let cache = new Map();

  return function get(p) {
    let fn = p.parentPath;
    while (fn && !t.isFunction(fn.node)) fn = fn.parentPath;
    if (!fn) return null;
    if (cache.has(fn.node)) return cache.get(fn.node);

    let consts = {};
    let aliases = {};

    for (let stmt of fn.node.body.body || []) {
      if (!t.isVariableDeclaration(stmt)) continue;

      for (let decl of stmt.declarations) {
        if (!t.isIdentifier(decl.id)) continue;
        let name = decl.id.name;

        if (t.isNumericLiteral(decl.init)) {
          consts[name] = decl.init.value;
        } else if (t.isIdentifier(decl.init) && chain[decl.init.name] !== undefined) {
          aliases[name] = chain[decl.init.name];
        } else if (t.isObjectExpression(decl.init)) {
          let obj = {};
          let ok = true;

          for (let prop of decl.init.properties) {
            if (!t.isObjectProperty(prop) || !t.isIdentifier(prop.key) || !t.isNumericLiteral(prop.value)) {
              ok = false;
              break;
            }
            obj[prop.key.name] = prop.value.value;
          }

          if (ok && Object.keys(obj).length > 0) consts[name] = obj;
        }
      }
    }

    let info = { consts, aliases };
    cache.set(fn.node, info);
    return info;
  };
}

function resolveNum(node, p, getLocal) {
  if (t.isNumericLiteral(node))
    return node.value;

  if (t.isIdentifier(node)) {
    let local = getLocal(p);
    if (local?.consts[node.name] !== undefined) return local.consts[node.name];
  }

  if (t.isMemberExpression(node) && !node.computed &&
      t.isIdentifier(node.object) && t.isIdentifier(node.property)) {
    let local = getLocal(p);
    let obj = local?.consts[node.object.name];
    if (obj && typeof obj === "object" && obj[node.property.name] !== undefined)
      return obj[node.property.name];
  }

  if (t.isUnaryExpression(node, { operator: "-" }) && t.isNumericLiteral(node.argument))
    return -node.argument.value;

  return undefined;
}

function resolveStrings(ast, blocks, accessors, chain, wrappers) {
  let getLocal = buildLocalCache(chain);
  let ch = 0;

  let blockMap = new Map();
  for (let b of blocks) {
    if (b.fn) blockMap.set(b.accessor, b);
  }

  traverse(ast, {
    noScope: true,
    CallExpression(p) {
      if (!t.isIdentifier(p.node.callee) || p.node.arguments.length < 1) return;
      let name = p.node.callee.name;

      let acc = accessors.has(name) ? name : chain[name] ?? null;
      if (!acc) {
        let local = getLocal(p);
        if (local?.aliases[name]) acc = local.aliases[name];
      }

      if (acc) {
        let block = blockMap.get(acc);
        if (!block) return;

        let num = resolveNum(p.node.arguments[0], p, getLocal);
        if (num === undefined) return;

        try {
          let val = block.fn(num);
          if (typeof val === "string") { p.replaceWith(t.stringLiteral(val)); ch++; }
        } catch {}
        return;
      }

      let w = wrappers[name];
      if (!w) return;

      let block = blockMap.get(w.accessor);
      if (!block) return;

      let arg = p.node.arguments[w.indexIdx];
      if (!arg) return;

      let num = resolveNum(arg, p, getLocal);
      if (num === undefined) return;

      try {
        let val = block.fn(num + w.offset);
        if (typeof val === "string") { p.replaceWith(t.stringLiteral(val)); ch++; }
      } catch {}
    },
  });

  return ch;
}

module.exports = { resolveStrings };

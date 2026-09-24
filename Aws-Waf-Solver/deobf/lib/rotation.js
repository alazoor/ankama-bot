const traverse = require("@babel/traverse").default;
const t = require("@babel/types");
const vm = require("vm");

const SKIP_KEYS = new Set(["parent", "leadingComments", "trailingComments"]);

function walk(node, fn) {
  if (!node || typeof node !== "object") return null;
  let r = fn(node);
  if (r) return r;

  for (let key of Object.keys(node)) {
    if (SKIP_KEYS.has(key)) continue;
    let val = node[key];

    if (Array.isArray(val)) {
      for (let item of val) {
        r = walk(item, fn);
        if (r) return r;
      }
    } else if (val?.type) {
      r = walk(val, fn);
      if (r) return r;
    }
  }

  return null;
}

function collect(node, fn) {
  if (!node || typeof node !== "object") return;
  fn(node);

  for (let key of Object.keys(node)) {
    if (SKIP_KEYS.has(key)) continue;
    let val = node[key];

    if (Array.isArray(val)) {
      for (let item of val) collect(item, fn);
    } else if (val?.type) {
      collect(val, fn);
    }
  }
}

function hasLargeArray(node) {
  return !!walk(node, n =>
    n.type === "ArrayExpression" && n.elements?.length > 20 || null
  );
}

function findOffset(body) {
  let offset = null;

  collect(body, n => {
    if (n.type === "AssignmentExpression" && n.operator === "-=" && t.isNumericLiteral(n.right))
      offset = n.right.value;
  });

  if (offset !== null) return offset;

  collect(body, n => {
    if (n.type === "BinaryExpression" && n.operator === "-" &&
        t.isNumericLiteral(n.right) && n.right.value > 0x50)
      offset = n.right.value;
  });

  return offset;
}

function findCalledGetter(body, getterNames) {
  let found = null;

  collect(body, n => {
    if (n.type === "CallExpression" && t.isIdentifier(n.callee) && getterNames.has(n.callee.name))
      found = n.callee.name;
  });

  return found;
}

function findRotationBlocks(ast) {
  let blocks = [];
  let getterMap = {};
  let getterNames = new Set();
  let fnDecls = [];
  let exprStmts = [];

  traverse(ast, {
    noScope: true,
    FunctionDeclaration(p) { fnDecls.push(p.node); },
    ExpressionStatement(p) { exprStmts.push(p.node); },
  });

  for (let fn of fnDecls) {
    let body = fn.body.body;
    if (body.length < 1 || body.length > 5 || !fn.id?.name) continue;
    if (!body.some(s => t.isReturnStatement(s))) continue;
    if (!hasLargeArray(fn.body)) continue;

    let block = { getter: fn.id.name, getterNode: fn };
    blocks.push(block);
    getterMap[fn.id.name] = block;
    getterNames.add(fn.id.name);
  }

  for (let fn of fnDecls) {
    if (!fn.id || fn.params.length !== 2) continue;

    let called = findCalledGetter(fn.body, getterNames);
    if (!called) continue;

    let offset = findOffset(fn.body);
    if (offset === null) continue;

    let block = getterMap[called];
    block.accessor = fn.id.name;
    block.accessorNode = fn;
    block.offset = offset;
  }

  for (let stmt of exprStmts) {
    let expr = stmt.expression;
    let call = t.isCallExpression(expr) ? expr
      : t.isUnaryExpression(expr) && t.isCallExpression(expr.argument) ? expr.argument
      : null;

    if (!call || !t.isFunctionExpression(call.callee) || call.arguments.length < 1) continue;

    let arg = call.arguments[0];
    if (t.isIdentifier(arg) && getterMap[arg.name])
      getterMap[arg.name].rotNode = stmt;
  }

  return blocks;
}

function bootstrapVM(ast, src, blocks) {
  let ctx = vm.createContext({
    parseInt, Number, isNaN, isFinite, String, Array, Object, Math, Boolean,
    Reflect, RangeError, TypeError, decodeURIComponent, encodeURIComponent,
    atob: s => Buffer.from(s, "base64").toString("binary"),
  });

  let decoderNames = new Set();
  let srcMap = {};
  let aliasPairs = [];

  traverse(ast, {
    noScope: true,
    FunctionDeclaration(p) {
      if (!p.node.id || !/^a0_0x/.test(p.node.id.name)) return;
      decoderNames.add(p.node.id.name);
      srcMap[p.node.id.name] = src.slice(p.node.start, p.node.end);
    },
    VariableDeclarator(p) {
      if (t.isIdentifier(p.node.id) && t.isIdentifier(p.node.init))
        aliasPairs.push([p.node.id.name, p.node.init.name]);
    },
  });

  if (decoderNames.size > 0) {
    let code = [...decoderNames].map(n => srcMap[n]).filter(Boolean).join(";\n") + ";";
    try { vm.runInContext(code, ctx); } catch {}
  }

  for (let [alias, target] of aliasPairs) {
    if (!decoderNames.has(target)) continue;
    try {
      vm.runInContext(`var ${alias} = ${target};`, ctx);
      decoderNames.add(alias);
    } catch {}
  }

  for (let block of blocks) {
    if (!block.accessor) continue;

    let code = src.slice(block.getterNode.start, block.getterNode.end) + ";\n"
             + src.slice(block.accessorNode.start, block.accessorNode.end) + ";";
    if (block.rotNode) code += "\n" + src.slice(block.rotNode.start, block.rotNode.end) + ";";

    try {
      vm.runInContext(code, ctx);
      block.fn = ctx[block.accessor];
    } catch {}
  }

  for (let name of decoderNames) {
    if (blocks.some(b => b.accessor === name)) continue;
    if (typeof ctx[name] === "function")
      blocks.push({ getter: null, accessor: name, fn: ctx[name], offset: 0 });
  }

  return { ctx, decoderNames };
}

function buildAliasChain(ast, blocks) {
  let accessors = new Set(blocks.filter(b => b.fn).map(b => b.accessor));
  let chain = {};

  for (let b of blocks)
    if (b.accessor) chain[b.accessor] = b.accessor;

  traverse(ast, {
    noScope: true,
    VariableDeclarator(p) {
      if (t.isIdentifier(p.node.id) && t.isIdentifier(p.node.init) && chain[p.node.init.name] !== undefined)
        chain[p.node.id.name] = chain[p.node.init.name];
    },
    AssignmentExpression(p) {
      if (t.isIdentifier(p.node.left) && t.isIdentifier(p.node.right) && chain[p.node.right.name] !== undefined)
        chain[p.node.left.name] = chain[p.node.right.name];
    },
  });

  return { accessors, chain };
}

function findWrappers(ast, accessors, chain) {
  let wrappers = {};

  traverse(ast, {
    noScope: true,
    FunctionDeclaration(p) {
      if (!p.node.id || p.node.params.length < 2) return;

      let body = p.node.body.body;
      if (body.length !== 1 || !t.isReturnStatement(body[0])) return;

      let ret = body[0].argument;
      if (!t.isCallExpression(ret) || ret.arguments.length !== 2 || !t.isIdentifier(ret.callee)) return;

      let callee = ret.callee.name;
      if (chain[callee] === undefined && !accessors.has(callee)) return;

      let params = p.node.params.map(pp => pp.name);
      let expr = ret.arguments[0];
      let keyParam = t.isIdentifier(ret.arguments[1]) ? ret.arguments[1].name : null;

      let indexParam = null;
      let offset = 0;

      if (t.isIdentifier(expr)) {
        indexParam = expr.name;
      } else if (t.isBinaryExpression(expr) && t.isIdentifier(expr.left) && t.isNumericLiteral(expr.right)) {
        indexParam = expr.left.name;
        offset = expr.operator === "+" ? expr.right.value : -expr.right.value;
      } else if (t.isBinaryExpression(expr) && expr.operator === "-" && t.isIdentifier(expr.left) &&
                 t.isUnaryExpression(expr.right, { operator: "-" }) && t.isNumericLiteral(expr.right.argument)) {
        indexParam = expr.left.name;
        offset = expr.right.argument.value;
      }

      if (!indexParam || !params.includes(indexParam)) return;
      if (keyParam && !params.includes(keyParam)) return;

      wrappers[p.node.id.name] = {
        accessor: chain[callee] || callee,
        indexIdx: params.indexOf(indexParam),
        keyIdx: keyParam ? params.indexOf(keyParam) : -1,
        offset,
      };
    },
  });

  return wrappers;
}

module.exports = { findRotationBlocks, bootstrapVM, buildAliasChain, findWrappers };

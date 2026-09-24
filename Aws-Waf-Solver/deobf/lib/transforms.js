const traverse = require("@babel/traverse").default;
const t = require("@babel/types");
const { SKIP, isIdent, tryDecodeB64, evalConst, toNode } = require("./utils");

function removeDeclarator(p) {
  if (t.isVariableDeclaration(p.parent) && p.parent.declarations.length === 1)
    p.parentPath.remove();
  else
    p.remove();
}

function inlineProxyObjects(ast) {
  let ch = 0;

  traverse(ast, {
    VariableDeclarator(p) {
      if (!t.isIdentifier(p.node.id) || !t.isObjectExpression(p.node.init)) return;
      if (p.node.init.properties.length === 0) return;

      let map = {};
      let ok = true;

      for (let prop of p.node.init.properties) {
        if (!t.isObjectProperty(prop)) { ok = false; break; }

        let key = t.isIdentifier(prop.key) ? prop.key.name
          : t.isStringLiteral(prop.key) ? prop.key.value : null;
        if (!key) { ok = false; break; }

        if (t.isFunctionExpression(prop.value)) {
          let body = prop.value.body.body;
          if (body.length !== 1 || !t.isReturnStatement(body[0])) { ok = false; break; }

          let ret = body[0].argument;
          let params = prop.value.params.map(pp => pp.name);

          if (t.isBinaryExpression(ret) && params.length === 2 &&
              t.isIdentifier(ret.left, { name: params[0] }) &&
              t.isIdentifier(ret.right, { name: params[1] }))
            map[key] = { type: "binary", op: ret.operator };
          else if (t.isCallExpression(ret) && t.isIdentifier(ret.callee) && ret.callee.name === params[0])
            map[key] = { type: "call" };
          else if (t.isLogicalExpression(ret) && params.length === 2 &&
              t.isIdentifier(ret.left, { name: params[0] }) &&
              t.isIdentifier(ret.right, { name: params[1] }))
            map[key] = { type: "logical", op: ret.operator };
          else { ok = false; break; }

        } else if (t.isStringLiteral(prop.value)) {
          map[key] = { type: "string", value: prop.value.value };
        } else {
          ok = false; break;
        }
      }

      if (!ok || Object.keys(map).length === 0) return;

      let binding = p.scope.getBinding(p.node.id.name);
      if (!binding) return;

      for (let ref of [...binding.referencePaths]) {
        if (ref.removed) continue;

        let mem = ref.parentPath;
        if (!mem?.node || !t.isMemberExpression(mem.node) || mem.node.object !== ref.node) continue;

        let key = t.isStringLiteral(mem.node.property) ? mem.node.property.value
          : t.isIdentifier(mem.node.property) && !mem.node.computed ? mem.node.property.name : null;
        if (!key || !map[key]) continue;

        let info = map[key];

        try {
          if (info.type === "string") {
            mem.replaceWith(t.stringLiteral(info.value));
            ch++;
          } else if (info.type === "binary" || info.type === "logical") {
            let call = mem.parentPath;
            if (!call?.node || !t.isCallExpression(call.node)) continue;
            if (call.node.callee !== mem.node || call.node.arguments.length !== 2) continue;

            let [l, r] = call.node.arguments;
            let node = info.type === "binary"
              ? t.binaryExpression(info.op, l, r)
              : t.logicalExpression(info.op, l, r);
            call.replaceWith(node);
            ch++;
          } else if (info.type === "call") {
            let call = mem.parentPath;
            if (!call?.node || !t.isCallExpression(call.node) || call.node.callee !== mem.node) continue;

            call.replaceWith(t.callExpression(call.node.arguments[0], call.node.arguments.slice(1)));
            ch++;
          }
        } catch {}
      }
    },
  });

  return ch;
}

function resolvePropsAndHex(ast) {
  let props = 0;
  let hex = 0;

  traverse(ast, {
    noScope: true,
    MemberExpression(p) {
      if (!p.node.computed || !t.isStringLiteral(p.node.property) || t.isSuper(p.node.object)) return;

      let k = p.node.property.value;
      let d = tryDecodeB64(k);

      if (d && isIdent(d)) {
        p.node.computed = false;
        p.node.property = t.identifier(d);
        props++;
      } else if (d) {
        p.node.property = t.stringLiteral(d);
        props++;
      } else if (isIdent(k)) {
        p.node.computed = false;
        p.node.property = t.identifier(k);
        props++;
      }
    },
    NumericLiteral(p) {
      if (p.node.extra?.raw && /^0x/i.test(p.node.extra.raw)) {
        delete p.node.extra;
        hex++;
      }
    },
  });

  return { props, hex };
}

const BINARY_OPS = {
  "+": (a, b) => a + b, "-": (a, b) => a - b,
  "*": (a, b) => a * b, "/": (a, b) => a / b,
  "%": (a, b) => a % b, "**": (a, b) => a ** b,
  "|": (a, b) => a | b, "&": (a, b) => a & b,
  "^": (a, b) => a ^ b, "<<": (a, b) => a << b,
  ">>": (a, b) => a >> b, ">>>": (a, b) => a >>> b,
  "===": (a, b) => a === b, "!==": (a, b) => a !== b,
  "==": (a, b) => a == b, "!=": (a, b) => a != b,
  "<": (a, b) => a < b, ">": (a, b) => a > b,
  "<=": (a, b) => a <= b, ">=": (a, b) => a >= b,
};

const UNARY_OPS = {
  "!": v => !v, "+": v => +v, "-": v => -v,
  "~": v => ~v, "typeof": v => typeof v, "void": () => undefined,
};

function foldConstants(ast) {
  let total = 0;

  for (let pass = 0; pass < 15; pass++) {
    let ch = 0;

    traverse(ast, {
      noScope: true,

      BinaryExpression: { exit(p) {
        let { operator: op, left: l, right: r } = p.node;
        let lc = evalConst(l), rc = evalConst(r);

        if (lc && rc && BINARY_OPS[op]) {
          let n = toNode(BINARY_OPS[op](lc.v, rc.v));
          if (n) { p.replaceWith(n); ch++; }
          return;
        }

        if (op !== "+") return;

        if (t.isStringLiteral(l) && t.isStringLiteral(r)) {
          p.replaceWith(t.stringLiteral(l.value + r.value));
          ch++;
        } else if (t.isBinaryExpression(l, { operator: "+" }) &&
                   t.isStringLiteral(l.right) && t.isStringLiteral(r)) {
          p.node.right = t.stringLiteral(l.right.value + r.value);
          p.node.left = l.left;
          ch++;
        }
      }},

      UnaryExpression: { exit(p) {
        if (p.node[SKIP]) return;

        if (p.node.operator === "void" && t.isNumericLiteral(p.node.argument, { value: 0 })) {
          p.replaceWith(t.identifier("undefined"));
          ch++;
          return;
        }

        let c = evalConst(p.node.argument);
        if (!c || !UNARY_OPS[p.node.operator]) return;

        let n = toNode(UNARY_OPS[p.node.operator](c.v));
        if (n) { p.replaceWith(n); ch++; }
      }},

      ConditionalExpression: { exit(p) {
        let c = evalConst(p.node.test);
        if (c) { p.replaceWith(c.v ? p.node.consequent : p.node.alternate); ch++; }
      }},

      LogicalExpression: { exit(p) {
        let lc = evalConst(p.node.left);
        if (!lc) return;

        if (p.node.operator === "&&")
          p.replaceWith(lc.v ? p.node.right : p.node.left);
        else if (p.node.operator === "||")
          p.replaceWith(lc.v ? p.node.left : p.node.right);
        else return;

        ch++;
      }},

      IfStatement(p) {
        let c = evalConst(p.node.test);
        if (!c) return;

        if (c.v) {
          t.isBlockStatement(p.node.consequent)
            ? p.replaceWithMultiple(p.node.consequent.body)
            : p.replaceWith(p.node.consequent);
        } else if (p.node.alternate) {
          t.isBlockStatement(p.node.alternate)
            ? p.replaceWithMultiple(p.node.alternate.body)
            : p.replaceWith(p.node.alternate);
        } else {
          p.remove();
        }

        ch++;
      },
    });

    total += ch;
    if (!ch) break;
  }

  return total;
}

function inlineGlobalAliases(ast) {
  let ch = 0;
  let globals = new Set(["window", "document", "navigator", "location"]);

  traverse(ast, {
    VariableDeclarator(p) {
      if (!t.isIdentifier(p.node.id) || !t.isIdentifier(p.node.init)) return;
      if (!globals.has(p.node.init.name)) return;

      let binding = p.scope.getBinding(p.node.id.name);
      if (!binding || binding.constantViolations.length > 0) return;

      for (let ref of binding.referencePaths)
        ref.replaceWith(t.identifier(p.node.init.name));

      removeDeclarator(p);
      ch += binding.referencePaths.length + 1;
    },
  });

  return ch;
}

function inlineConstArrays(ast) {
  let ch = 0;

  traverse(ast, {
    VariableDeclarator(p) {
      if (!t.isIdentifier(p.node.id) || !t.isArrayExpression(p.node.init)) return;

      let elems = p.node.init.elements;
      if (elems.length === 0 || elems.length > 200) return;

      let allConst = elems.every(e => e &&
        (t.isStringLiteral(e) || t.isNumericLiteral(e) || t.isBooleanLiteral(e) || t.isNullLiteral(e)));
      if (!allConst) return;

      let binding = p.scope.getBinding(p.node.id.name);
      if (!binding || binding.constantViolations.length > 0) return;

      let replaced = 0;

      for (let ref of [...binding.referencePaths]) {
        if (ref.removed) continue;

        let mem = ref.parentPath;
        if (!mem?.node || !t.isMemberExpression(mem.node)) continue;
        if (mem.node.object !== ref.node || !mem.node.computed) continue;
        if (!t.isNumericLiteral(mem.node.property)) continue;

        let idx = mem.node.property.value;
        if (idx < 0 || idx >= elems.length) continue;

        let elem = elems[idx];
        try {
          if (t.isStringLiteral(elem)) mem.replaceWith(t.stringLiteral(elem.value));
          else if (t.isNumericLiteral(elem)) mem.replaceWith(t.numericLiteral(elem.value));
          else if (t.isBooleanLiteral(elem)) mem.replaceWith(t.booleanLiteral(elem.value));
          else if (t.isNullLiteral(elem)) mem.replaceWith(t.nullLiteral());
          else continue;
          replaced++;
          ch++;
        } catch {}
      }

      if (replaced > 0 && binding.referencePaths.every(r => r.removed)) {
        removeDeclarator(p);
        ch++;
      }
    },
  });

  return ch;
}

function simplifyAndDot(ast) {
  let seqs = 0;
  let dots = 0;

  traverse(ast, {
    noScope: true,
    ExpressionStatement(p) {
      if (!t.isSequenceExpression(p.node.expression)) return;

      let exprs = p.node.expression.expressions;
      if (exprs.length < 2) return;

      p.replaceWithMultiple(exprs.map(e => t.expressionStatement(e)));
      seqs++;
    },
    MemberExpression(p) {
      if (!p.node.computed || !t.isStringLiteral(p.node.property)) return;
      if (t.isSuper(p.node.object) || !isIdent(p.node.property.value)) return;

      p.node.computed = false;
      p.node.property = t.identifier(p.node.property.value);
      dots++;
    },
  });

  return { seqs, dots };
}

function cleanupDeadCode(ast, decoderNames, chain, blocks) {
  let ch = 0;

  let dead = new Set(decoderNames);
  for (let b of blocks) if (b.accessor) dead.add(b.accessor);
  for (let k of Object.keys(chain)) { dead.add(k); dead.add(chain[k]); }

  let counts = {};
  traverse(ast, {
    noScope: true,
    Identifier(p) { counts[p.node.name] = (counts[p.node.name] || 0) + 1; },
  });

  traverse(ast, {
    noScope: true,
    VariableDeclarator(p) {
      if (!t.isIdentifier(p.node.id) || !t.isIdentifier(p.node.init)) return;
      if (!dead.has(p.node.init.name)) return;
      if ((counts[p.node.id.name] || 0) > 2) return;
      removeDeclarator(p);
      ch++;
    },
    FunctionDeclaration(p) {
      if (p.node.id && decoderNames.has(p.node.id.name)) {
        p.remove();
        ch++;
      }
    },
  });

  traverse(ast, {
    noScope: true,
    VariableDeclaration(p) { if (p.node.declarations.length === 0) p.remove(); },
    EmptyStatement(p) { p.remove(); },
  });

  return ch;
}

module.exports = {
  inlineProxyObjects,
  resolvePropsAndHex,
  foldConstants,
  inlineGlobalAliases,
  inlineConstArrays,
  simplifyAndDot,
  cleanupDeadCode,
};

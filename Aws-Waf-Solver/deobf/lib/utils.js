const t = require("@babel/types");

const SKIP = Symbol("skip");
const IDENT_START = /^[a-zA-Z_$]/;
const IDENT_BODY = /^[a-zA-Z0-9_$]+$/;
const B64_CHARS = /^[A-Za-z0-9+/=]+$/;
const B64_MIXED = /[a-z].*[A-Z].*[0-9]|[A-Z].*[a-z].*[0-9]|[0-9].*[a-z].*[A-Z]/;
const UNPRINTABLE = /[\x00-\x08\x0e-\x1f\x7f-\xff]/;

function isIdent(s) {
  return s?.length > 0 && IDENT_START.test(s) && IDENT_BODY.test(s);
}

function tryDecodeB64(s) {
  if (s.length < 8 || !B64_CHARS.test(s)) return null;
  if (!B64_MIXED.test(s) && !s.endsWith("=")) return null;

  try {
    let d = Buffer.from(s, "base64").toString("binary");
    return d.length >= 2 && !UNPRINTABLE.test(d) ? d : null;
  } catch {
    return null;
  }
}

function evalConst(node) {
  if (t.isNullLiteral(node)) return { v: null };
  if (t.isIdentifier(node, { name: "undefined" })) return { v: undefined };
  if (t.isIdentifier(node, { name: "NaN" })) return { v: NaN };
  if (t.isIdentifier(node, { name: "Infinity" })) return { v: Infinity };
  if (t.isNumericLiteral(node) || t.isStringLiteral(node) || t.isBooleanLiteral(node))
    return { v: node.value };
  return null;
}

function toNode(v) {
  if (v === null) return t.nullLiteral();
  if (v === undefined) return t.identifier("undefined");
  if (typeof v === "boolean") return t.booleanLiteral(v);

  if (typeof v === "number") {
    if (Object.is(v, -0)) return _neg(t.numericLiteral(0));
    if (isNaN(v)) return t.identifier("NaN");
    if (!isFinite(v)) return v > 0 ? t.identifier("Infinity") : _neg(t.identifier("Infinity"));
    if (v < 0) return _neg(t.numericLiteral(-v));
    return t.numericLiteral(v);
  }

  if (typeof v === "string") return t.stringLiteral(v);
  return null;
}

function _neg(arg) {
  let n = t.unaryExpression("-", arg);
  n[SKIP] = true;
  return n;
}

module.exports = { SKIP, isIdent, tryDecodeB64, evalConst, toNode };

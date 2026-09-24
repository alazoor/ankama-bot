const parser = require("@babel/parser");
const generate = require("@babel/generator").default;
const fs = require("fs");

const { findRotationBlocks, bootstrapVM, buildAliasChain, findWrappers } = require("./lib/rotation");
const { resolveStrings } = require("./lib/resolver");
const tx = require("./lib/transforms");

let input = process.argv[2] || "challenge.js";
let output = input.replace(/\.js$/, ".clean.js");
let src = fs.readFileSync(input, "utf8");

let start = Date.now();
let ast = parser.parse(src, { sourceType: "script", allowReturnOutsideFunction: true });

function elapsed(t) { return (Date.now() - t) + "ms"; }

function step(name, fn) {
  let t = Date.now();
  let result = fn();
  console.log(`  ${name}: ${elapsed(t)} | ${JSON.stringify(result)}`);
  return result;
}

console.log("deobfuscating " + input + "...\n");

let t0 = Date.now();
let blocks = findRotationBlocks(ast);
let { decoderNames } = bootstrapVM(ast, src, blocks);
let { accessors, chain } = buildAliasChain(ast, blocks);
let wrappers = findWrappers(ast, accessors, chain);
console.log(`  rotation: ${elapsed(t0)} | blocks=${blocks.filter(b => b.fn).length} wrappers=${Object.keys(wrappers).length}`);

step("strings", () => resolveStrings(ast, blocks, accessors, chain, wrappers));
step("proxy-objects", () => tx.inlineProxyObjects(ast));
step("props+hex", () => tx.resolvePropsAndHex(ast));
step("const-fold", () => tx.foldConstants(ast));
step("props (pass 2)", () => tx.resolvePropsAndHex(ast));
step("global-aliases", () => tx.inlineGlobalAliases(ast));
step("dead-code", () => tx.cleanupDeadCode(ast, decoderNames, chain, blocks));
step("const-arrays", () => tx.inlineConstArrays(ast));
step("seq+dot", () => tx.simplifyAndDot(ast));

let t1 = Date.now();
fs.writeFileSync(output, generate(ast, { comments: false, compact: false }).code);
console.log(`  codegen: ${elapsed(t1)}`);

console.log(`\ndone in ${elapsed(start)} -> ${output}`);

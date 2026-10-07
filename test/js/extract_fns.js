// test/js/extract_fns.js — v5.30: 前端逻辑测试的小工具。
//
// webroot/js/*.js 是浏览器脚本(全局函数, 顶层会碰 document / localStorage),
// 不能直接 require。这里按名字把顶层 `function 名字(` 声明的源码抽出来
// (括号配对时跳过字符串与注释), 放进一个干净的 vm 上下文里执行, 返回这些
// 函数 —— 测的是仓库里真实的函数体, 不是测试里重写的一份。
'use strict';
const fs = require('fs');
const vm = require('vm');

function extract(src, name) {
  const re = new RegExp('(^|\\n)function ' + name + '\\s*\\(');
  const m = re.exec(src);
  if (!m) throw new Error('function not found: ' + name);
  const start = m.index + m[1].length;
  let i = src.indexOf('{', m.index + m[0].length);
  // 跳过参数表里的默认值之类(本项目不用), 从函数体第一个 { 开始配对
  let depth = 0;
  for (; i < src.length; i++) {
    const c = src[i];
    if (c === '"' || c === "'" || c === '`') {
      for (i++; i < src.length && src[i] !== c; i++) if (src[i] === '\\') i++;
      continue;
    }
    if (c === '/' && src[i + 1] === '/') { i = src.indexOf('\n', i); if (i < 0) break; continue; }
    if (c === '/' && src[i + 1] === '*') { i = src.indexOf('*/', i) + 1; continue; }
    if (c === '{') depth++;
    else if (c === '}' && --depth === 0) return src.slice(start, i + 1);
  }
  throw new Error('unbalanced function: ' + name);
}

// load(文件, [函数名...], 额外全局) → vm 上下文(函数挂在上面)
function load(file, names, globals) {
  const src = fs.readFileSync(file, 'utf8');
  const ctx = vm.createContext(Object.assign({}, globals || {}));
  vm.runInContext(names.map((n) => extract(src, n)).join('\n'), ctx, { filename: file });
  return ctx;
}

module.exports = { extract, load };

import { callAt, stringAt } from '../source.ts';
import type { Rule } from '../types.ts';
import { isMemberCall, matches, preview } from './util.ts';

const SENSITIVE = /PerformHttpRequest|loadstring|\bload\b|\bassert\b|RegisterCommand|ExecuteCommand|os\.execute|io\.popen|\b_G\b|\brequire\b|\beval\b|\bFunction\b|child_process|https?:\/\/|GetConvar|sv_licenseKey|webhook/;
const STRING_CHAR = /\bstring\s*\.\s*char\s*(?=\()/g;
const GLOBAL_INDEX = /\b(_G|_ENV|getfenv\s*\(\s*\d*\s*\))\s*\[/g;
const MIN_ESCAPES = 12;
const LONG_LINE = 2500;
const MINIFIED = /\.min\.js$|(?:^|\/)(?:html|ui|web|nui|dist|build)\//i;

export const obfuscation: Rule = {
  id: 'FA003',
  name: 'obfuscated-code',
  severity: 'high',
  description: 'Escaped byte strings, string.char chains, dynamic global lookups or packed lines that hide what the code really does. Legitimate resources have no reason to hide API names.',
  languages: ['lua', 'js'],
  check(file, report) {
    for (const literal of file.strings) {
      if (literal.escapes < MIN_ESCAPES) continue;
      const rawLength = literal.contentEnd - literal.contentStart;
      if (literal.escapes < literal.value.length * 0.6) continue;
      const hidden = SENSITIVE.test(literal.value);
      report({
        offset: literal.start,
        length: Math.min(rawLength + 2, 80),
        severity: hidden ? 'critical' : 'high',
        message: hidden ? `Escaped string hides "${preview(literal.value, 48)}"` : `String encoded as ${literal.escapes} byte escapes`,
      });
    }

    if (file.language === 'lua') {
      for (const m of matches(file.code, STRING_CHAR)) {
        const call = callAt(file.code, m.index + m[0].length);
        if (call === undefined || call.args.length < 8) continue;
        const bytes = call.args.map((a) => file.code.slice(a.start, a.end).trim());
        if (!bytes.every((b) => /^(?:\d{1,3}|0x[0-9a-fA-F]{1,2})$/.test(b))) continue;
        const decoded = String.fromCharCode(...bytes.map((b) => Number(b) & 0xff));
        report({
          offset: m.index,
          length: m[0].length,
          severity: SENSITIVE.test(decoded) ? 'critical' : 'high',
          message: `string.char() builds "${preview(decoded, 48)}" from ${bytes.length} bytes`,
        });
      }
      for (const m of matches(file.code, GLOBAL_INDEX)) {
        if (isMemberCall(file.code, m.index)) continue;
        const open = m.index + m[0].length - 1;
        let close = open;
        let depth = 0;
        for (; close < file.code.length; close++) {
          if (file.code[close] === '[') depth++;
          else if (file.code[close] === ']' && --depth === 0) break;
        }
        const inner = { start: open + 1, end: close };
        const trimmed = file.code.slice(inner.start, inner.end).trim();
        const offsetStart = inner.start + file.code.slice(inner.start, inner.end).indexOf(trimmed);
        const literal = stringAt(file.strings, { start: offsetStart, end: offsetStart + trimmed.length });
        if (literal !== undefined && literal.escapes === 0) continue;
        report({
          offset: m.index,
          length: m[0].length,
          severity: literal !== undefined ? 'high' : 'low',
          message: literal !== undefined ? `${m[1]} indexed with escaped name "${preview(literal.value, 32)}"` : `${m[1]} indexed with a computed name hides which global is used`,
        });
      }
    }

    let lineStart = 0;
    while (lineStart <= file.text.length) {
      const next = file.text.indexOf('\n', lineStart);
      const end = next === -1 ? file.text.length : next;
      if (end - lineStart > LONG_LINE) {
        const segment = file.code.slice(lineStart, end);
        const dense = file.language === 'lua' || (!MINIFIED.test(file.path) && /\beval\s*\(|\bnew\s+Function\s*\(/.test(segment));
        if (dense && /[;)\]]\s*[\w$]/.test(segment)) {
          report({ offset: lineStart, length: 1, severity: 'medium', message: `Packed line of ${end - lineStart} characters` });
        }
      }
      if (next === -1) break;
      lineStart = next + 1;
    }
  },
};

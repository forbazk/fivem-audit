import type { StringLiteral } from './types.ts';

export interface Lexed {
  readonly code: string;
  readonly strings: StringLiteral[];
}

const SPACE = ' ';

function blankText(segment: string): string {
  return segment.replace(/[^\n]/g, SPACE);
}

function lineEnd(source: string, from: number): number {
  const at = source.indexOf('\n', from);
  return at === -1 ? source.length : at;
}

function quotedEnd(source: string, from: number, quote: string): number {
  let j = from;
  while (j < source.length) {
    const c = source[j];
    if (c === '\\') {
      j += 2;
      continue;
    }
    if (c === quote || c === '\n') break;
    j++;
  }
  return Math.min(j, source.length);
}

function longBracketLevel(source: string, index: number): number {
  if (source[index] !== '[') return -1;
  let i = index + 1;
  while (source[i] === '=') i++;
  return source[i] === '[' ? i - index - 1 : -1;
}

function findLongClose(source: string, from: number, level: number): { contentEnd: number; end: number } {
  const at = source.indexOf(']' + '='.repeat(level) + ']', from);
  return at === -1 ? { contentEnd: source.length, end: source.length } : { contentEnd: at, end: at + level + 2 };
}

const SIMPLE_ESCAPES: Readonly<Record<string, string>> = {
  n: '\n',
  t: '\t',
  r: '\r',
  a: '\x07',
  b: '\b',
  f: '\f',
  v: '\v',
  '\\': '\\',
  '"': '"',
  "'": "'",
  '`': '`',
  '\n': '\n',
};

interface Decoded {
  readonly value: string;
  readonly escapes: number;
}

function codePoint(hex: string, max: number): string | undefined {
  if (!/^[0-9a-fA-F]+$/.test(hex) || hex.length > max) return undefined;
  const cp = parseInt(hex, 16);
  return cp <= 0x10ffff ? String.fromCodePoint(cp) : '';
}

function decodeLuaEscapes(raw: string): Decoded {
  if (!raw.includes('\\')) return { value: raw, escapes: 0 };
  let value = '';
  let escapes = 0;
  for (let i = 0; i < raw.length; i++) {
    const ch = raw[i]!;
    if (ch !== '\\') {
      value += ch;
      continue;
    }
    const next = raw[i + 1];
    if (next === undefined) break;
    if (next >= '0' && next <= '9') {
      const digits = /^\d{1,3}/.exec(raw.slice(i + 1, i + 4))![0];
      value += String.fromCharCode(Number(digits) & 0xff);
      escapes++;
      i += digits.length;
      continue;
    }
    if (next === 'x' && /^[0-9a-fA-F]{2}$/.test(raw.slice(i + 2, i + 4))) {
      value += String.fromCharCode(parseInt(raw.slice(i + 2, i + 4), 16));
      escapes++;
      i += 3;
      continue;
    }
    if (next === 'u' && raw[i + 2] === '{') {
      const end = raw.indexOf('}', i + 3);
      const decoded = end === -1 ? undefined : codePoint(raw.slice(i + 3, end), 8);
      if (decoded !== undefined) {
        value += decoded;
        escapes++;
        i = end;
        continue;
      }
    }
    if (next === 'z') {
      let j = i + 2;
      while (j < raw.length && /\s/.test(raw[j]!)) j++;
      i = j - 1;
      continue;
    }
    value += SIMPLE_ESCAPES[next] ?? next;
    i++;
  }
  return { value, escapes };
}

function decodeJsEscapes(raw: string): Decoded {
  if (!raw.includes('\\')) return { value: raw, escapes: 0 };
  let value = '';
  let escapes = 0;
  for (let i = 0; i < raw.length; i++) {
    const ch = raw[i]!;
    if (ch !== '\\') {
      value += ch;
      continue;
    }
    const next = raw[i + 1];
    if (next === undefined) break;
    if (next === 'x' && /^[0-9a-fA-F]{2}$/.test(raw.slice(i + 2, i + 4))) {
      value += String.fromCharCode(parseInt(raw.slice(i + 2, i + 4), 16));
      escapes++;
      i += 3;
      continue;
    }
    if (next === 'u') {
      if (raw[i + 2] === '{') {
        const end = raw.indexOf('}', i + 3);
        const decoded = end === -1 ? undefined : codePoint(raw.slice(i + 3, end), 6);
        if (decoded !== undefined) {
          value += decoded;
          escapes++;
          i = end;
          continue;
        }
      } else if (/^[0-9a-fA-F]{4}$/.test(raw.slice(i + 2, i + 6))) {
        value += String.fromCharCode(parseInt(raw.slice(i + 2, i + 6), 16));
        escapes++;
        i += 5;
        continue;
      }
    }
    if (next >= '0' && next <= '7') {
      const digits = /^[0-7]{1,3}/.exec(raw.slice(i + 1, i + 4))![0];
      value += String.fromCharCode(parseInt(digits, 8) & 0xff);
      escapes++;
      i += digits.length;
      continue;
    }
    value += SIMPLE_ESCAPES[next] ?? next;
    i++;
  }
  return { value, escapes };
}

const LUA_TOKEN = /--|["'[]/g;

export function lexLua(source: string): Lexed {
  const parts: string[] = [];
  const strings: StringLiteral[] = [];
  const token = new RegExp(LUA_TOKEN.source, 'g');
  let last = 0;
  for (let m = token.exec(source); m !== null; m = token.exec(source)) {
    const i = m.index;
    const tok = m[0];
    let end: number;
    if (tok === '--') {
      const level = longBracketLevel(source, i + 2);
      end = level >= 0 ? findLongClose(source, i + 4 + level, level).end : lineEnd(source, i);
      parts.push(source.slice(last, i), blankText(source.slice(i, end)));
    } else if (tok === '[') {
      const level = longBracketLevel(source, i);
      if (level < 0) continue;
      const contentStart = i + level + 2;
      const close = findLongClose(source, contentStart, level);
      end = close.end;
      const raw = source.slice(contentStart, close.contentEnd);
      strings.push({ start: i, end, contentStart, contentEnd: close.contentEnd, value: raw.startsWith('\n') ? raw.slice(1) : raw, escapes: 0, template: false });
      parts.push(source.slice(last, contentStart), blankText(raw), source.slice(close.contentEnd, end));
    } else {
      const contentEnd = quotedEnd(source, i + 1, tok);
      end = source[contentEnd] === tok ? contentEnd + 1 : contentEnd;
      const raw = source.slice(i + 1, contentEnd);
      const decoded = decodeLuaEscapes(raw);
      strings.push({ start: i, end, contentStart: i + 1, contentEnd, value: decoded.value, escapes: decoded.escapes, template: false });
      parts.push(source.slice(last, i + 1), blankText(raw), source.slice(contentEnd, end));
    }
    last = end;
    token.lastIndex = end;
  }
  parts.push(source.slice(last));
  return { code: parts.join(''), strings };
}

const REGEX_PRECEDERS = new Set(['(', ',', '=', ':', '[', '!', '&', '|', '?', '{', '}', ';', '+', '-', '*', '%', '<', '>', '~', '^']);
const REGEX_KEYWORDS = new Set(['return', 'typeof', 'instanceof', 'in', 'of', 'new', 'delete', 'void', 'throw', 'case', 'do', 'else', 'yield', 'await']);

function regexAllowed(source: string, index: number): boolean {
  let j = index - 1;
  while (j >= 0 && /\s/.test(source[j]!)) j--;
  if (j < 0) return true;
  const prev = source[j]!;
  if (REGEX_PRECEDERS.has(prev)) return true;
  if (/[\w$]/.test(prev)) {
    let k = j;
    while (k >= 0 && /[\w$]/.test(source[k]!)) k--;
    return REGEX_KEYWORDS.has(source.slice(k + 1, j + 1));
  }
  return false;
}

function regexEnd(source: string, from: number): number {
  let inClass = false;
  for (let j = from; j < source.length; j++) {
    const c = source[j];
    if (c === '\n') return -1;
    if (c === '\\') {
      j++;
      continue;
    }
    if (c === '[') inClass = true;
    else if (c === ']') inClass = false;
    else if (c === '/' && !inClass) return j;
  }
  return -1;
}

const JS_TOKEN = /\/\/|\/\*|["'`/{}]/g;

export function lexJs(source: string): Lexed {
  const parts: string[] = [];
  const strings: StringLiteral[] = [];
  const templateDepths: number[] = [];
  const token = new RegExp(JS_TOKEN.source, 'g');
  let braceDepth = 0;
  let last = 0;

  const flush = (to: number): void => {
    parts.push(source.slice(last, to));
    last = to;
  };

  const blankRange = (from: number, to: number): void => {
    flush(from);
    parts.push(blankText(source.slice(from, to)));
    last = to;
  };

  const readTemplate = (from: number): number => {
    let j = from;
    while (j < source.length) {
      const c = source[j];
      if (c === '\\') {
        j += 2;
        continue;
      }
      if (c === '`' || (c === '$' && source[j + 1] === '{')) break;
      j++;
    }
    const contentEnd = Math.min(j, source.length);
    const raw = source.slice(from, contentEnd);
    const decoded = decodeJsEscapes(raw);
    const closing = source[contentEnd] === '`';
    strings.push({ start: from - 1, end: closing ? contentEnd + 1 : contentEnd, contentStart: from, contentEnd, value: decoded.value, escapes: decoded.escapes, template: true });
    blankRange(from, contentEnd);
    if (closing) return contentEnd + 1;
    if (contentEnd < source.length) {
      templateDepths.push(braceDepth);
      braceDepth = 0;
      return contentEnd + 2;
    }
    return contentEnd;
  };

  for (let m = token.exec(source); m !== null; m = token.exec(source)) {
    const i = m.index;
    const tok = m[0];
    let next = i + tok.length;
    if (tok === '//') {
      next = lineEnd(source, i);
      blankRange(i, next);
    } else if (tok === '/*') {
      const close = source.indexOf('*/', i + 2);
      next = close === -1 ? source.length : close + 2;
      blankRange(i, next);
    } else if (tok === '"' || tok === "'") {
      const contentEnd = quotedEnd(source, i + 1, tok);
      next = source[contentEnd] === tok ? contentEnd + 1 : contentEnd;
      const decoded = decodeJsEscapes(source.slice(i + 1, contentEnd));
      strings.push({ start: i, end: next, contentStart: i + 1, contentEnd, value: decoded.value, escapes: decoded.escapes, template: false });
      blankRange(i + 1, contentEnd);
    } else if (tok === '`') {
      next = readTemplate(i + 1);
    } else if (tok === '{') {
      braceDepth++;
    } else if (tok === '}') {
      if (braceDepth === 0 && templateDepths.length > 0) {
        braceDepth = templateDepths.pop()!;
        next = readTemplate(i + 1);
      } else {
        braceDepth = Math.max(0, braceDepth - 1);
      }
    } else if (regexAllowed(source, i)) {
      const end = regexEnd(source, i + 1);
      if (end !== -1) {
        blankRange(i + 1, end);
        next = end + 1;
      }
    }
    token.lastIndex = next;
  }
  flush(source.length);
  return { code: parts.join(''), strings };
}

const SCRIPT_BLOCK = /<script\b[^>]*>([\s\S]*?)<\/script\s*>/gi;

export function lexHtml(source: string): Lexed {
  const parts: string[] = [];
  let last = 0;
  SCRIPT_BLOCK.lastIndex = 0;
  for (let m = SCRIPT_BLOCK.exec(source); m !== null; m = SCRIPT_BLOCK.exec(source)) {
    const bodyStart = m.index + m[0].indexOf('>') + 1;
    const bodyEnd = bodyStart + m[1]!.length;
    parts.push(blankText(source.slice(last, bodyStart)), source.slice(bodyStart, bodyEnd));
    last = bodyEnd;
  }
  parts.push(blankText(source.slice(last)));
  return lexJs(parts.join(''));
}

export function lexText(source: string): Lexed {
  return { code: source, strings: [] };
}

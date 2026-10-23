import type { StringLiteral } from './types.ts';

export interface Lexed {
  readonly code: string;
  readonly strings: StringLiteral[];
}

const NEWLINE = 10;
const SPACE = ' ';

function blank(source: string, from: number, to: number, out: string[]): void {
  for (let i = from; i < to; i++) {
    out[i] = source.charCodeAt(i) === NEWLINE ? '\n' : SPACE;
  }
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

function decodeLuaEscapes(raw: string): { value: string; escapes: number } {
  let value = '';
  let escapes = 0;
  for (let i = 0; i < raw.length; i++) {
    const ch = raw[i];
    if (ch !== '\\') {
      value += ch;
      continue;
    }
    const next = raw[i + 1];
    if (next === undefined) break;
    if (next >= '0' && next <= '9') {
      let digits = next;
      let j = i + 2;
      while (digits.length < 3 && raw[j] !== undefined && raw[j]! >= '0' && raw[j]! <= '9') {
        digits += raw[j];
        j++;
      }
      value += String.fromCharCode(Number(digits) & 0xff);
      escapes++;
      i = j - 1;
      continue;
    }
    if (next === 'x') {
      const hex = raw.slice(i + 2, i + 4);
      if (/^[0-9a-fA-F]{2}$/.test(hex)) {
        value += String.fromCharCode(parseInt(hex, 16));
        escapes++;
        i += 3;
        continue;
      }
    }
    if (next === 'u' && raw[i + 2] === '{') {
      const end = raw.indexOf('}', i + 3);
      const hex = end === -1 ? '' : raw.slice(i + 3, end);
      if (/^[0-9a-fA-F]{1,8}$/.test(hex)) {
        const cp = parseInt(hex, 16);
        value += cp <= 0x10ffff ? String.fromCodePoint(cp) : '';
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
  '\n': '\n',
};

function decodeJsEscapes(raw: string): { value: string; escapes: number } {
  let value = '';
  let escapes = 0;
  for (let i = 0; i < raw.length; i++) {
    const ch = raw[i];
    if (ch !== '\\') {
      value += ch;
      continue;
    }
    const next = raw[i + 1];
    if (next === undefined) break;
    if (next === 'x') {
      const hex = raw.slice(i + 2, i + 4);
      if (/^[0-9a-fA-F]{2}$/.test(hex)) {
        value += String.fromCharCode(parseInt(hex, 16));
        escapes++;
        i += 3;
        continue;
      }
    }
    if (next === 'u') {
      if (raw[i + 2] === '{') {
        const end = raw.indexOf('}', i + 3);
        const hex = end === -1 ? '' : raw.slice(i + 3, end);
        if (/^[0-9a-fA-F]{1,6}$/.test(hex)) {
          const cp = parseInt(hex, 16);
          value += cp <= 0x10ffff ? String.fromCodePoint(cp) : '';
          escapes++;
          i = end;
          continue;
        }
      } else {
        const hex = raw.slice(i + 2, i + 6);
        if (/^[0-9a-fA-F]{4}$/.test(hex)) {
          value += String.fromCharCode(parseInt(hex, 16));
          escapes++;
          i += 5;
          continue;
        }
      }
    }
    if (next >= '0' && next <= '7') {
      let digits = next;
      let j = i + 2;
      while (digits.length < 3 && raw[j] !== undefined && raw[j]! >= '0' && raw[j]! <= '7') {
        digits += raw[j];
        j++;
      }
      value += String.fromCharCode(parseInt(digits, 8) & 0xff);
      escapes++;
      i = j - 1;
      continue;
    }
    value += SIMPLE_ESCAPES[next] ?? (next === '0' ? '\0' : next);
    i++;
  }
  return { value, escapes };
}

const LUA_TOKEN = /--|["'[]/g;

function blankText(segment: string): string {
  return segment.replace(/[^\n]/g, SPACE);
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
      const decoded = raw.includes('\\') ? decodeLuaEscapes(raw) : { value: raw, escapes: 0 };
      strings.push({ start: i, end, contentStart: i + 1, contentEnd, value: decoded.value, escapes: decoded.escapes, template: false });
      parts.push(source.slice(last, i + 1), blankText(raw), source.slice(contentEnd, end));
    }
    last = end;
    token.lastIndex = end;
  }
  parts.push(source.slice(last));
  return { code: parts.join(''), strings };
}

function lineEnd(source: string, from: number): number {
  const at = source.indexOf('\n', from);
  return at === -1 ? source.length : at;
}

const REGEX_PRECEDERS = new Set(['', '(', ',', '=', ':', '[', '!', '&', '|', '?', '{', '}', ';', '+', '-', '*', '%', '<', '>', '~', '^']);
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

export function lexJs(source: string): Lexed {
  const out = source.split('');
  const strings: StringLiteral[] = [];
  const length = source.length;
  const templateStack: number[] = [];
  let braceDepth = 0;
  let i = 0;

  const readTemplate = (from: number): number => {
    let j = from;
    let segmentStart = from;
    while (j < length) {
      const c = source[j];
      if (c === '\\') {
        j += 2;
        continue;
      }
      if (c === '`') {
        pushTemplate(segmentStart, j, j + 1);
        return j + 1;
      }
      if (c === '$' && source[j + 1] === '{') {
        pushTemplate(segmentStart, j, j);
        templateStack.push(braceDepth);
        braceDepth = 0;
        return j + 2;
      }
      j++;
    }
    pushTemplate(segmentStart, length, length);
    return length;
  };

  const pushTemplate = (contentStart: number, contentEnd: number, end: number): void => {
    const decoded = decodeJsEscapes(source.slice(contentStart, contentEnd));
    strings.push({ start: contentStart - 1, end, contentStart, contentEnd, value: decoded.value, escapes: decoded.escapes, template: true });
    blank(source, contentStart, contentEnd, out);
  };

  while (i < length) {
    const ch = source[i];
    const next = source[i + 1];
    if (ch === '/' && next === '/') {
      const end = lineEnd(source, i);
      blank(source, i, end, out);
      i = end;
      continue;
    }
    if (ch === '/' && next === '*') {
      const close = source.indexOf('*/', i + 2);
      const end = close === -1 ? length : close + 2;
      blank(source, i, end, out);
      i = end;
      continue;
    }
    if (ch === '"' || ch === "'") {
      let j = i + 1;
      while (j < length) {
        const c = source[j];
        if (c === '\\') {
          j += 2;
          continue;
        }
        if (c === ch || c === '\n') break;
        j++;
      }
      const contentEnd = Math.min(j, length);
      const end = source[contentEnd] === ch ? contentEnd + 1 : contentEnd;
      const decoded = decodeJsEscapes(source.slice(i + 1, contentEnd));
      strings.push({ start: i, end, contentStart: i + 1, contentEnd, value: decoded.value, escapes: decoded.escapes, template: false });
      blank(source, i + 1, contentEnd, out);
      i = end;
      continue;
    }
    if (ch === '`') {
      i = readTemplate(i + 1);
      continue;
    }
    if (ch === '{') {
      braceDepth++;
      i++;
      continue;
    }
    if (ch === '}') {
      if (braceDepth === 0 && templateStack.length > 0) {
        braceDepth = templateStack.pop()!;
        i = readTemplate(i + 1);
        continue;
      }
      braceDepth = Math.max(0, braceDepth - 1);
      i++;
      continue;
    }
    if (ch === '/' && regexAllowed(source, i)) {
      let j = i + 1;
      let inClass = false;
      while (j < length) {
        const c = source[j];
        if (c === '\n') break;
        if (c === '\\') {
          j += 2;
          continue;
        }
        if (c === '[') inClass = true;
        else if (c === ']') inClass = false;
        else if (c === '/' && !inClass) break;
        j++;
      }
      if (source[j] === '/') {
        blank(source, i + 1, j, out);
        i = j + 1;
        continue;
      }
    }
    i++;
  }
  return { code: out.join(''), strings };
}

export function lexText(source: string): Lexed {
  return { code: source, strings: [] };
}

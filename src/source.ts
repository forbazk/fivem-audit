import { lexJs, lexLua, lexText } from './lexer.ts';
import type { Language, Position, Side, SourceFile, StringLiteral } from './types.ts';

export interface SourceInit {
  readonly absolutePath: string;
  readonly path: string;
  readonly resource: string;
  readonly language: Language;
  readonly side: Side;
  readonly text: string;
}

function lineStarts(text: string): Uint32Array {
  const starts = [0];
  for (let i = text.indexOf('\n'); i !== -1; i = text.indexOf('\n', i + 1)) starts.push(i + 1);
  return Uint32Array.from(starts);
}

export function createSource(init: SourceInit): SourceFile {
  const lexed = init.language === 'lua' ? lexLua(init.text) : init.language === 'js' ? lexJs(init.text) : lexText(init.text);
  const starts = lineStarts(init.text);
  const text = init.text;

  const position = (offset: number): Position => {
    let lo = 0;
    let hi = starts.length - 1;
    while (lo < hi) {
      const mid = (lo + hi + 1) >>> 1;
      if (starts[mid]! <= offset) lo = mid;
      else hi = mid - 1;
    }
    return { line: lo + 1, column: offset - starts[lo]! + 1 };
  };

  const lineText = (line: number): string => {
    const start = starts[line - 1];
    if (start === undefined) return '';
    const next = starts[line];
    const end = next === undefined ? text.length : next - 1;
    return text.slice(start, end).replace(/\r$/, '');
  };

  return { ...init, code: lexed.code, strings: lexed.strings, position, lineText };
}

const PAREN_OPEN = 40;
const PAREN_CLOSE = 41;
const BRACKET_OPEN = 91;
const BRACKET_CLOSE = 93;
const BRACE_OPEN = 123;
const BRACE_CLOSE = 125;
const COMMA = 44;

function closerOf(code: number): number {
  return code === PAREN_OPEN ? PAREN_CLOSE : code === BRACKET_OPEN ? BRACKET_CLOSE : code === BRACE_OPEN ? BRACE_CLOSE : -1;
}

function isCloser(code: number): boolean {
  return code === PAREN_CLOSE || code === BRACKET_CLOSE || code === BRACE_CLOSE;
}

export function matchBracket(code: string, open: number): number {
  const stack: number[] = [];
  for (let i = open; i < code.length; i++) {
    const c = code.charCodeAt(i);
    const closer = closerOf(c);
    if (closer !== -1) {
      stack.push(closer);
      continue;
    }
    if (isCloser(c)) {
      if (stack.pop() !== c) return -1;
      if (stack.length === 0) return i;
    }
  }
  return -1;
}

export interface Span {
  readonly start: number;
  readonly end: number;
}

export function splitArguments(code: string, open: number, close: number): Span[] {
  const args: Span[] = [];
  let depth = 0;
  let start = open + 1;
  for (let i = open + 1; i < close; i++) {
    const c = code.charCodeAt(i);
    if (closerOf(c) !== -1) depth++;
    else if (isCloser(c)) depth--;
    else if (c === COMMA && depth === 0) {
      args.push(trimSpan(code, start, i));
      start = i + 1;
    }
  }
  const last = trimSpan(code, start, close);
  if (last.end > last.start || args.length > 0) args.push(last);
  return args;
}

function isSpace(c: number): boolean {
  return c === 32 || (c >= 9 && c <= 13);
}

function trimSpan(code: string, start: number, end: number): Span {
  let s = start;
  let e = end;
  while (s < e && isSpace(code.charCodeAt(s))) s++;
  while (e > s && isSpace(code.charCodeAt(e - 1))) e--;
  return { start: s, end: e };
}

export function callAt(code: string, nameEnd: number): { open: number; close: number; args: Span[] } | undefined {
  let open = nameEnd;
  while (open < code.length && /\s/.test(code[open]!)) open++;
  if (code[open] !== '(') return undefined;
  const close = matchBracket(code, open);
  if (close === -1) return undefined;
  return { open, close, args: splitArguments(code, open, close) };
}

export function stringAt(strings: readonly StringLiteral[], span: Span): StringLiteral | undefined {
  let lo = 0;
  let hi = strings.length - 1;
  while (lo <= hi) {
    const mid = (lo + hi) >>> 1;
    const s = strings[mid]!;
    if (s.start < span.start) lo = mid + 1;
    else if (s.start > span.start) hi = mid - 1;
    else return s.end === span.end ? s : undefined;
  }
  return undefined;
}

export function stringsWithin(strings: readonly StringLiteral[], span: Span): StringLiteral[] {
  let lo = 0;
  let hi = strings.length;
  while (lo < hi) {
    const mid = (lo + hi) >>> 1;
    if (strings[mid]!.start < span.start) lo = mid + 1;
    else hi = mid;
  }
  const found: StringLiteral[] = [];
  for (let i = lo; i < strings.length; i++) {
    const s = strings[i]!;
    if (s.start >= span.end) break;
    if (s.end <= span.end) found.push(s);
  }
  return found;
}

const LUA_BLOCK = /\b(function|if|do|repeat|end|until)\b/g;

export function luaBlockEnd(code: string, bodyStart: number): number {
  LUA_BLOCK.lastIndex = bodyStart;
  let depth = 1;
  for (let m = LUA_BLOCK.exec(code); m !== null; m = LUA_BLOCK.exec(code)) {
    if (isMemberAccess(code, m.index)) continue;
    const word = m[1];
    if (word === 'end' || word === 'until') depth--;
    else depth++;
    if (depth === 0) return m.index;
  }
  return code.length;
}

function isMemberAccess(code: string, index: number): boolean {
  let j = index - 1;
  while (j >= 0 && (code[j] === ' ' || code[j] === '\t')) j--;
  return j >= 0 && (code[j] === '.' || code[j] === ':') && code[j - 1] !== '.';
}

export interface LuaFunction {
  readonly start: number;
  readonly params: readonly string[];
  readonly bodyStart: number;
  readonly bodyEnd: number;
}

export function luaFunctionIn(code: string, span: Span): LuaFunction | undefined {
  const head = /\bfunction\s*\(([^)]*)\)/g;
  head.lastIndex = span.start;
  const m = head.exec(code);
  if (m === null || m.index >= span.end) return undefined;
  const bodyStart = m.index + m[0].length;
  const params = (m[1] ?? '')
    .split(',')
    .map((p) => p.trim())
    .filter((p) => /^[A-Za-z_]\w*$/.test(p));
  return { start: m.index, params, bodyStart, bodyEnd: luaBlockEnd(code, bodyStart) };
}

export function hasTopLevel(code: string, span: Span, token: string): boolean {
  const first = token.charCodeAt(0);
  let depth = 0;
  for (let i = span.start; i < span.end; i++) {
    const c = code.charCodeAt(i);
    if (closerOf(c) !== -1) depth++;
    else if (isCloser(c)) depth--;
    else if (depth === 0 && c === first && code.startsWith(token, i)) return true;
  }
  return false;
}

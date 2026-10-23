import type { SourceFile, StringLiteral } from '../types.ts';
import type { Span } from '../source.ts';
import { stringAt } from '../source.ts';

export function* matches(code: string, pattern: RegExp, from = 0, to = code.length): Generator<RegExpExecArray> {
  const re = new RegExp(pattern.source, pattern.flags.includes('g') ? pattern.flags : pattern.flags + 'g');
  re.lastIndex = from;
  for (let m = re.exec(code); m !== null && m.index < to; m = re.exec(code)) {
    if (m[0].length === 0) re.lastIndex++;
    yield m;
  }
}

export function isMemberCall(code: string, index: number): boolean {
  let j = index - 1;
  while (j >= 0 && (code[j] === ' ' || code[j] === '\t')) j--;
  return j >= 0 && (code[j] === ':' || (code[j] === '.' && code[j - 1] !== '.'));
}

export function literalArgument(file: SourceFile, span: Span | undefined): StringLiteral | undefined {
  return span === undefined ? undefined : stringAt(file.strings, span);
}

export function isPureLiteral(file: SourceFile, span: Span | undefined): boolean {
  return literalArgument(file, span) !== undefined;
}

export function identifiersIn(code: string, span: Span): Set<string> {
  const ids = new Set<string>();
  for (const m of matches(code, /(?<![.:\w$])[A-Za-z_$][\w$]*/g, span.start, span.end)) {
    if (m.index + m[0].length <= span.end) ids.add(m[0]);
  }
  return ids;
}

export function preview(value: string, max = 60): string {
  const flat = value.replace(/\s+/g, ' ').trim();
  return flat.length > max ? `${flat.slice(0, max - 1)}…` : flat;
}

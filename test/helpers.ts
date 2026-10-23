import { analyze } from '../src/scanner.ts';
import { createSource } from '../src/source.ts';
import type { Finding, Language, Side } from '../src/types.ts';

export function source(text: string, language: Language = 'lua', side: Side = 'server', path = 'res/server/main.lua') {
  return createSource({ absolutePath: path, path, resource: 'res', language, side, text });
}

export function findings(text: string, language: Language = 'lua', side: Side = 'server', path?: string): Finding[] {
  return analyze(source(text, language, side, path ?? (language === 'js' ? 'res/server/main.js' : language === 'text' ? 'res/config.cfg' : 'res/server/main.lua')));
}

export function ids(text: string, language: Language = 'lua', side: Side = 'server', path?: string): string[] {
  return findings(text, language, side, path).map((f) => f.ruleId);
}

export function only(text: string, ruleId: string, language: Language = 'lua', side: Side = 'server', path?: string): Finding[] {
  return findings(text, language, side, path).filter((f) => f.ruleId === ruleId);
}

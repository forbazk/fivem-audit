import { lexLua } from './lexer.ts';
import { matchBracket } from './source.ts';
import type { Side } from './types.ts';

export interface Manifest {
  readonly server: readonly RegExp[];
  readonly client: readonly RegExp[];
  readonly shared: readonly RegExp[];
}

export const EMPTY_MANIFEST: Manifest = { server: [], client: [], shared: [] };

export function globToRegExp(glob: string): RegExp {
  let pattern = '';
  const normalized = glob.replace(/\\/g, '/').replace(/^\.\//, '');
  for (let i = 0; i < normalized.length; i++) {
    const ch = normalized[i]!;
    if (ch === '*') {
      if (normalized[i + 1] === '*') {
        if (normalized[i + 2] === '/') {
          pattern += '(?:.*/)?';
          i += 2;
        } else {
          pattern += '.*';
          i += 1;
        }
      } else {
        pattern += '[^/]*';
      }
    } else if (ch === '?') {
      pattern += '[^/]';
    } else {
      pattern += ch.replace(/[.+^${}()|[\]\\]/g, '\\$&');
    }
  }
  return new RegExp(`^${pattern}$`, 'i');
}

const ENTRY = /\b(server|client|shared)_scripts?\b/g;

export function parseManifest(source: string): Manifest {
  const { code, strings } = lexLua(source);
  const buckets: Record<'server' | 'client' | 'shared', RegExp[]> = { server: [], client: [], shared: [] };
  ENTRY.lastIndex = 0;
  for (let m = ENTRY.exec(code); m !== null; m = ENTRY.exec(code)) {
    const kind = m[1] as 'server' | 'client' | 'shared';
    let i = m.index + m[0].length;
    while (i < code.length && /\s/.test(code[i]!)) i++;
    let start = i;
    let end: number;
    const ch = code[i];
    if (ch === '{' || ch === '(') {
      end = matchBracket(code, i);
      if (end === -1) continue;
    } else if (ch === '"' || ch === "'" || ch === '[') {
      const literal = strings.find((s) => s.start === i);
      if (literal === undefined) continue;
      start = literal.start;
      end = literal.end;
    } else {
      continue;
    }
    for (const literal of strings) {
      if (literal.start < start || literal.end > end + 1) continue;
      const value = literal.value.trim();
      if (value === '' || value.startsWith('@') || /^https?:/i.test(value)) continue;
      buckets[kind].push(globToRegExp(value));
    }
    ENTRY.lastIndex = end;
  }
  return buckets;
}

const SERVER_PATH = /(?:^|[/_.-])(?:server|sv)(?:[/_.-]|$)/i;
const CLIENT_PATH = /(?:^|[/_.-])(?:client|cl)(?:[/_.-]|$)/i;

export function sideOf(manifest: Manifest, path: string): Side {
  const normalized = path.replace(/\\/g, '/');
  const server = manifest.server.some((r) => r.test(normalized));
  const client = manifest.client.some((r) => r.test(normalized));
  const shared = manifest.shared.some((r) => r.test(normalized));
  if (shared || (server && client)) return 'shared';
  if (server) return 'server';
  if (client) return 'client';
  if (SERVER_PATH.test(normalized)) return 'server';
  if (CLIENT_PATH.test(normalized)) return 'client';
  return 'unknown';
}

import { callAt, hasTopLevel, stringsWithin } from '../source.ts';
import type { Rule, SourceFile } from '../types.ts';
import type { Span } from '../source.ts';
import { matches } from './util.ts';

const LUA_QUERY = /\bMySQL\s*\.\s*(?:Async|Sync)\s*\.\s*\w+\s*(?=\()|\bMySQL\s*\.\s*(?:query|single|scalar|insert|update|prepare|execute|transaction|rawExecute|fetch)(?:\s*\.\s*await)?\s*(?=\()|\bexports\s*(?:\.\s*\w+|\[\s*["'][^"']*["']\s*\])\s*:\s*(?:query|single|scalar|insert|update|prepare|execute|fetch|transaction|rawExecute|query_async|execute_async|scalar_async|insert_async|single_async)\w*\s*(?=\()/g;
const JS_QUERY = /\b(?:MySQL|oxmysql|exports\s*\.\s*oxmysql|exports\s*\[\s*["'][^"']*["']\s*\]|db|pool|connection|conn|knex)\s*\.\s*(?:query|execute|single|scalar|insert|update|prepare|rawExecute|raw)\s*(?=\()/g;
const DB_EXPORT = /oxmysql|ghmattimysql|mysql-async|mysql/i;
const SQL_WORD = /\b(?:select|insert|update|delete|replace|where|from|into|values|set|order\s+by|limit)\b/i;

function looksLikeSql(file: SourceFile, span: Span): boolean {
  return stringsWithin(file.strings, span).some((s) => SQL_WORD.test(s.value));
}

export const sqlInjection: Rule = {
  id: 'FA005',
  name: 'sql-injection',
  severity: 'high',
  description: 'A SQL query is assembled with string concatenation, string.format or template literals. Use parameter placeholders (?) so player input can never change the query.',
  languages: ['lua', 'js'],
  check(file, report) {
    const pattern = file.language === 'lua' ? LUA_QUERY : JS_QUERY;
    for (const m of matches(file.code, pattern)) {
      if (m[0].startsWith('exports') && !DB_EXPORT.test(file.text.slice(m.index, m.index + m[0].length))) continue;
      const call = callAt(file.code, m.index + m[0].length);
      const arg = call?.args[0];
      if (arg === undefined) continue;
      const argCode = file.code.slice(arg.start, arg.end);
      let how: string | undefined;
      if (file.language === 'lua') {
        if (hasTopLevel(file.code, arg, '..')) how = 'string concatenation';
        else if (/(?:\bstring\s*\.\s*format|:\s*format)\s*\(/.test(argCode) && stringsWithin(file.strings, arg).some((s) => /%[sdq]/.test(s.value))) how = 'string.format';
      } else {
        const templates = stringsWithin(file.strings, arg).filter((s) => s.template);
        if (templates.length > 1) how = 'template literal interpolation';
        else if (hasTopLevel(file.code, arg, '+')) how = 'string concatenation';
      }
      if (how === undefined || !looksLikeSql(file, arg)) continue;
      report({ offset: m.index, length: m[0].trim().length, message: `SQL query built with ${how}; use ? placeholders` });
    }
  },
};

import { callAt, luaFunctionIn, matchBracket } from '../source.ts';
import type { Span } from '../source.ts';
import type { Rule, SourceFile } from '../types.ts';
import { identifiersIn, isMemberCall, literalArgument, matches } from './util.ts';

const LUA_REGISTER = /\b(RegisterNetEvent|RegisterServerEvent|AddEventHandler)\s*(?=\()/g;
const JS_REGISTER = /\b(onNet|on)\s*(?=\()/g;
const SINK = /\b(addMoney|addAccountMoney|AddMoney|setMoney|SetMoney|setAccountMoney|addBank|AddBank|addInventoryItem|AddItem|addItem|giveItem|GiveItem|canCarryItem|addWeapon|AddWeapon|giveWeapon|GiveWeapon|GiveWeaponToPed|setJob|SetJob|setGroup|SetGroup|SetPermission|AddPrincipal|ExecuteCommand|SetPlayerMetaData|setMeta|SetMetaData|addXP|AddXP|addVehicle|SetVehicleOwner|setVehicleOwner)\s*(?=\()/g;
const GUARD = /\b(?:if|assert)\b[^\n]*(?:source|src|xPlayer|Player|player|amount|count|price|group|job|ace|IsPlayerAceAllowed)/;
const SOURCE_REF = /\b(?:source|src|playerId|_source)\b/;

interface Handler {
  readonly name: string;
  readonly at: number;
  readonly params: readonly string[];
  readonly body: Span;
}

function luaHandlers(file: SourceFile): Handler[] {
  const net = new Set<string>();
  const candidates: { name: string; at: number; fn: Span }[] = [];
  for (const m of matches(file.code, LUA_REGISTER)) {
    if (isMemberCall(file.code, m.index)) continue;
    const call = callAt(file.code, m.index + m[0].length);
    if (call === undefined) continue;
    const name = literalArgument(file, call.args[0])?.value;
    if (name === undefined) continue;
    if (m[1] !== 'AddEventHandler') net.add(name);
    const fn = call.args[1];
    if (fn !== undefined) candidates.push({ name, at: m.index, fn });
  }
  const handlers: Handler[] = [];
  for (const c of candidates) {
    if (!net.has(c.name)) continue;
    const fn = luaFunctionIn(file.code, c.fn);
    if (fn === undefined) continue;
    handlers.push({ name: c.name, at: c.at, params: fn.params, body: { start: fn.bodyStart, end: fn.bodyEnd } });
  }
  return handlers;
}

function jsHandlers(file: SourceFile): Handler[] {
  const handlers: Handler[] = [];
  for (const m of matches(file.code, JS_REGISTER)) {
    if (m[1] === 'on' && !/\bonNet\b|\bemitNet\b/.test(file.code)) continue;
    if (isMemberCall(file.code, m.index) && m[1] === 'on') continue;
    const call = callAt(file.code, m.index + m[0].length);
    const fnSpan = call?.args[1];
    const name = literalArgument(file, call?.args[0])?.value;
    if (call === undefined || fnSpan === undefined || name === undefined) continue;
    const head = /^(?:async\s+)?(?:function\s*\w*\s*\(([^)]*)\)|\(([^)]*)\)\s*=>|([A-Za-z_$][\w$]*)\s*=>)/.exec(file.code.slice(fnSpan.start, fnSpan.end));
    if (head === null) continue;
    const params = (head[1] ?? head[2] ?? head[3] ?? '')
      .split(',')
      .map((p) => p.replace(/[=:].*$/, '').replace(/^\.\.\./, '').trim())
      .filter((p) => /^[A-Za-z_$][\w$]*$/.test(p));
    const brace = file.code.indexOf('{', fnSpan.start + head[0].length);
    if (brace === -1 || brace >= fnSpan.end) continue;
    const close = matchBracket(file.code, brace);
    if (close === -1) continue;
    handlers.push({ name, at: m.index, params, body: { start: brace + 1, end: close } });
  }
  return handlers;
}

export const netEvents: Rule = {
  id: 'FA006',
  name: 'unvalidated-net-event',
  severity: 'high',
  description: 'A server event reachable from any client passes its arguments straight into money, item, job or permission functions. Cheaters trigger these events directly with arbitrary values.',
  languages: ['lua', 'js'],
  check(file, report) {
    if (file.side === 'client') return;
    const handlers = file.language === 'lua' ? luaHandlers(file) : jsHandlers(file);
    for (const handler of handlers) {
      if (handler.params.length === 0) continue;
      const params = new Set(handler.params);
      for (const sink of matches(file.code, SINK, handler.body.start, handler.body.end)) {
        const call = callAt(file.code, sink.index + sink[0].length);
        if (call === undefined || call.close > handler.body.end) continue;
        const used = [...identifiersIn(file.code, { start: call.open, end: call.close })].filter((id) => params.has(id));
        if (used.length === 0) continue;
        const before = file.code.slice(handler.body.start, sink.index);
        const guarded = GUARD.test(before);
        const checksSource = SOURCE_REF.test(before);
        report({
          offset: sink.index,
          length: sink[1]!.length,
          severity: guarded ? 'medium' : 'high',
          message: `Net event "${handler.name}" passes client value ${used.map((u) => `"${u}"`).join(', ')} to ${sink[1]}()${guarded ? '' : checksSource ? ' without validating it' : ' with no server-side check'}`,
        });
      }
    }
  },
};

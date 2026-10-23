import { callAt, hasTopLevel } from '../source.ts';
import type { Rule } from '../types.ts';
import { isMemberCall, isPureLiteral, matches } from './util.ts';

const LUA_LOADERS = /\b(loadstring|load|dofile|loadfile)\s*(?=\()/g;
const LUA_HTTP_ANY = /\bPerformHttpRequest\b/;
const LUA_HTTP = /\bPerformHttpRequest\s*(?=\()/g;
const LUA_EXEC = /\b(load|loadstring)\s*\(/;
const LUA_OS = /\b(os|io)\s*\.\s*(execute|popen|remove|rename|open|lines|exit)\s*(?=\()/g;
const LUA_COMMAND = /\bExecuteCommand\s*(?=\()/g;

const JS_EVAL = /\beval\s*(?=\()|\bnew\s+Function\s*(?=\()|\bvm\s*\.\s*(?:runInNewContext|runInThisContext|runInContext|compileFunction)\s*(?=\()|\bnew\s+vm\s*\.\s*Script\s*(?=\()/g;
const JS_CHILD = /\brequire\s*\(\s*(["'`])(?:node:)?child_process\1\s*\)|\bfrom\s+(["'])(?:node:)?child_process\2|\bimport\s*\(\s*(["'`])(?:node:)?child_process\3\s*\)/g;
const JS_NET = /\b(?:fetch|axios(?:\s*\.\s*(?:get|post|request))?|https?\s*\.\s*(?:get|request)|PerformHttpRequest|request)\s*\(/;
const JS_RUN = /\beval\s*\(|\bnew\s+Function\s*\(|\bvm\s*\.\s*run\w*\s*\(/;

export const dynamicCode: Rule = {
  id: 'FA001',
  name: 'dynamic-code-execution',
  severity: 'medium',
  description: 'Code is compiled or executed at runtime (load, loadstring, dofile, eval, new Function). This is the core primitive of almost every FiveM backdoor.',
  languages: ['lua', 'js'],
  check(file, report) {
    if (file.language === 'lua') {
      for (const m of matches(file.code, LUA_LOADERS)) {
        if (isMemberCall(file.code, m.index)) continue;
        const name = m[1]!;
        const call = callAt(file.code, m.index + m[0].length);
        if (call === undefined) continue;
        if (name === 'dofile' || name === 'loadfile') {
          report({ offset: m.index, length: name.length, severity: 'medium', message: `${name}() loads and runs Lua from disk at runtime` });
          continue;
        }
        const arg = call.args[0];
        const argCode = arg === undefined ? '' : file.text.slice(arg.start, arg.end);
        if (isPureLiteral(file, arg)) {
          report({ offset: m.index, length: name.length, severity: 'low', message: `${name}() compiles a constant string; prefer plain code` });
        } else if (/\bLoadResourceFile\s*\(\s*GetCurrentResourceName\s*\(\s*\)/.test(argCode)) {
          report({ offset: m.index, length: name.length, severity: 'low', message: `${name}() runs a file bundled with this resource` });
        } else {
          const networked = LUA_HTTP_ANY.test(file.code);
          report({
            offset: m.index,
            length: name.length,
            severity: networked ? 'high' : 'medium',
            message: networked ? `${name}() compiles a runtime value in a file that also performs HTTP requests` : `${name}() compiles a runtime value into executable code`,
          });
        }
      }
      return;
    }
    for (const m of matches(file.code, JS_EVAL)) {
      if (m[0].startsWith('eval') && isMemberCall(file.code, m.index)) continue;
      const networked = JS_NET.test(file.code);
      report({
        offset: m.index,
        length: m[0].trim().length,
        severity: networked ? 'high' : 'medium',
        message: `${m[0].trim()}() executes a runtime string as code${networked ? ' in a file that also performs network requests' : ''}`,
      });
    }
  },
};

export const remoteExecution: Rule = {
  id: 'FA002',
  name: 'remote-code-execution',
  severity: 'critical',
  description: 'An HTTP response is executed as code. This is the signature of remote-controlled backdoors that let a third party run arbitrary code on the server.',
  languages: ['lua', 'js'],
  check(file, report) {
    if (file.language === 'lua') {
      for (const m of matches(file.code, LUA_HTTP)) {
        if (isMemberCall(file.code, m.index)) continue;
        const call = callAt(file.code, m.index + m[0].length);
        if (call === undefined) continue;
        const callback = file.code.slice(call.open, call.close);
        if (LUA_EXEC.test(callback)) {
          report({ offset: m.index, length: 18, message: 'PerformHttpRequest callback passes the response to load(): remote code execution' });
        }
      }
      return;
    }
    const net = JS_NET.exec(file.code);
    if (net === null) return;
    const window = file.code.slice(net.index, net.index + 4000);
    const run = JS_RUN.exec(window);
    if (run !== null) {
      report({ offset: net.index + run.index, length: run[0].length, message: 'Network response flows into dynamic code execution: remote code execution' });
    }
  },
};

export const systemAccess: Rule = {
  id: 'FA007',
  name: 'system-access',
  severity: 'critical',
  description: 'Shell commands, process spawning or raw filesystem access from a resource. FiveM resources almost never need this; malware uses it to persist and spread.',
  languages: ['lua', 'js'],
  check(file, report) {
    if (file.language === 'lua') {
      for (const m of matches(file.code, LUA_OS)) {
        if (isMemberCall(file.code, m.index)) continue;
        const fn = `${m[1]}.${m[2]}`;
        const severity = fn === 'os.execute' || fn === 'io.popen' ? 'critical' : fn === 'os.exit' ? 'medium' : 'high';
        report({ offset: m.index, length: m[0].length, severity, message: `${fn}() gives the resource ${severity === 'critical' ? 'shell access' : 'direct OS access'}` });
      }
      for (const m of matches(file.code, LUA_COMMAND)) {
        if (isMemberCall(file.code, m.index)) continue;
        const call = callAt(file.code, m.index + m[0].length);
        const arg = call?.args[0];
        if (arg === undefined || isPureLiteral(file, arg)) continue;
        const built = hasTopLevel(file.code, arg, '..') || /\bformat\s*\(/.test(file.code.slice(arg.start, arg.end));
        report({
          offset: m.index,
          length: 14,
          severity: built ? 'high' : 'medium',
          message: built ? 'ExecuteCommand() runs a console command built from runtime values' : 'ExecuteCommand() runs a console command from a variable',
        });
      }
      return;
    }
    for (const m of matches(file.text, JS_CHILD)) {
      if (file.code[m.index] !== file.text[m.index]) continue;
      report({ offset: m.index, length: m[0].length, message: 'child_process gives the resource shell access' });
    }
  },
};

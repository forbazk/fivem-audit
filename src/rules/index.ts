import type { Rule } from '../types.ts';
import { dynamicCode, remoteExecution, systemAccess } from './code-execution.ts';
import { netEvents } from './net-events.ts';
import { legacyManifest, suspiciousHosts } from './network.ts';
import { obfuscation } from './obfuscation.ts';
import { secrets } from './secrets.ts';
import { sqlInjection } from './sql.ts';

export const RULES: readonly Rule[] = [
  dynamicCode,
  remoteExecution,
  obfuscation,
  secrets,
  sqlInjection,
  netEvents,
  systemAccess,
  suspiciousHosts,
  legacyManifest,
];

export function ruleById(id: string): Rule | undefined {
  return RULES.find((r) => r.id === id);
}

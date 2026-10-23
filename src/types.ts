export type Severity = 'info' | 'low' | 'medium' | 'high' | 'critical';

export const SEVERITIES: readonly Severity[] = ['info', 'low', 'medium', 'high', 'critical'];

export function severityRank(severity: Severity): number {
  return SEVERITIES.indexOf(severity);
}

export function isSeverity(value: string): value is Severity {
  return (SEVERITIES as readonly string[]).includes(value);
}

export type Language = 'lua' | 'js' | 'text';

export type Side = 'server' | 'client' | 'shared' | 'unknown';

export interface StringLiteral {
  readonly start: number;
  readonly end: number;
  readonly contentStart: number;
  readonly contentEnd: number;
  readonly value: string;
  readonly escapes: number;
  readonly template: boolean;
}

export interface Position {
  readonly line: number;
  readonly column: number;
}

export interface SourceFile {
  readonly absolutePath: string;
  readonly path: string;
  readonly resource: string;
  readonly language: Language;
  readonly side: Side;
  readonly text: string;
  readonly code: string;
  readonly strings: readonly StringLiteral[];
  position(offset: number): Position;
  lineText(line: number): string;
}

export interface Finding {
  readonly ruleId: string;
  readonly severity: Severity;
  readonly message: string;
  readonly resource: string;
  readonly file: string;
  readonly line: number;
  readonly column: number;
  readonly snippet: string;
}

export interface Match {
  readonly offset: number;
  readonly length?: number;
  readonly message: string;
  readonly severity?: Severity;
  readonly redact?: boolean;
}

export type Report = (match: Match) => void;

export interface Rule {
  readonly id: string;
  readonly name: string;
  readonly severity: Severity;
  readonly description: string;
  readonly languages: readonly Language[];
  check(file: SourceFile, report: Report): void;
}

export interface ResourceResult {
  readonly name: string;
  readonly path: string;
  readonly manifest: 'fxmanifest' | 'legacy' | 'none';
  readonly files: number;
  readonly score: number;
  readonly findings: readonly Finding[];
}

export interface ScanStats {
  readonly files: number;
  readonly skipped: number;
  readonly bytes: number;
  readonly durationMs: number;
}

export interface ScanResult {
  readonly roots: readonly string[];
  readonly resources: readonly ResourceResult[];
  readonly findings: readonly Finding[];
  readonly stats: ScanStats;
}

export interface ScanOptions {
  readonly ignore?: readonly string[];
  readonly maxFileSize?: number;
  readonly concurrency?: number;
  readonly rules?: readonly Rule[];
  readonly minSeverity?: Severity;
}

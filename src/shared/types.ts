/**
 * Every check (dependencies, headers, secrets) reports its results as a
 * flat list of Findings, regardless of how different their internal
 * logic is. This shared shape is what lets the CLI print a single,
 * unified report instead of three differently-formatted outputs.
 */
export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

export interface Finding {
  /** Which check produced this finding, e.g. "dependencies", "headers", "secrets" */
  source: string;
  severity: Severity;
  /** Short, one-line summary shown in the report table */
  title: string;
  /** Extra detail: file path, package name + version, header name, etc. */
  detail: string;
  /** Optional actionable suggestion */
  recommendation?: string;
}

export interface CheckResult {
  checkName: string;
  findings: Finding[];
  /** Set when the check could not run at all (e.g. network unreachable) */
  error?: string;
}

// Order used to sort findings so the most urgent ones appear first.
export const SEVERITY_ORDER: Record<Severity, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
};

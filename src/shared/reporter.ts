import chalk from 'chalk';
import { CheckResult, Finding, SEVERITY_ORDER, Severity } from './types';

const SEVERITY_COLOR: Record<Severity, (text: string) => string> = {
  critical: chalk.bgRed.white.bold,
  high: chalk.red.bold,
  medium: chalk.yellow,
  low: chalk.blue,
  info: chalk.gray,
};

function sortBySeverity(findings: Finding[]): Finding[] {
  return [...findings].sort((a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity]);
}

/**
 * Prints a human-readable report to stdout. Kept separate from the
 * checks themselves so the checks stay UI-agnostic (they just return
 * data) — this function is the only place that knows about colors,
 * layout, and terminal formatting.
 */
export function printReport(results: CheckResult[]): void {
  console.log(chalk.bold('\n🔒 Security Audit Report\n'));

  let totalFindings = 0;

  for (const result of results) {
    console.log(chalk.underline.bold(result.checkName));

    if (result.error) {
      console.log(chalk.gray(`  ⚠ Skipped: ${result.error}\n`));
      continue;
    }

    if (result.findings.length === 0) {
      console.log(chalk.green('  ✓ No issues found\n'));
      continue;
    }

    for (const finding of sortBySeverity(result.findings)) {
      totalFindings++;
      const badge = SEVERITY_COLOR[finding.severity](` ${finding.severity.toUpperCase()} `);
      console.log(`  ${badge} ${finding.title}`);
      console.log(`    ${chalk.dim(finding.detail)}`);
      if (finding.recommendation) {
        console.log(`    ${chalk.cyan('→')} ${finding.recommendation}`);
      }
    }
    console.log('');
  }

  const summary =
    totalFindings === 0
      ? chalk.green.bold('✓ No security issues found.')
      : chalk.bold(`Found ${totalFindings} issue(s) across ${results.length} check(s).`);

  console.log(summary + '\n');
}

/**
 * Non-zero exit code when there are findings at or above "high" severity.
 * This is what lets the tool be wired into a CI pipeline as a gate,
 * not just a report you have to read manually.
 */
export function hasBlockingFindings(results: CheckResult[]): boolean {
  return results.some((r) =>
    r.findings.some((f) => f.severity === 'critical' || f.severity === 'high')
  );
}

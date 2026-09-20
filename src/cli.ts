#!/usr/bin/env node
import { Command } from 'commander';
import { resolve } from 'path';
import { checkDependencies } from './checks/dependencies';
import { checkHeaders } from './checks/headers';
import { checkSecrets } from './checks/secrets';
import { printReport, hasBlockingFindings } from './shared/reporter';
import { CheckResult } from './shared/types';

const program = new Command();

program
  .name('secaudit')
  .description('A lightweight CLI security auditor: vulnerable dependencies, insecure HTTP headers, and leaked secrets.')
  .version('1.0.0');

program
  .command('deps')
  .description('Scan package-lock.json for dependencies with known vulnerabilities (via OSV.dev)')
  .argument('[path]', 'path to the project directory', '.')
  .action(async (path: string) => {
    await runAndReport('Dependency vulnerabilities', () => checkDependencies(resolve(path)));
  });

program
  .command('headers')
  .description('Check a live URL for missing or weak security-related HTTP headers')
  .argument('<url>', 'the URL to check, e.g. https://example.com')
  .action(async (url: string) => {
    await runAndReport(`HTTP security headers (${url})`, () => checkHeaders(url));
  });

program
  .command('secrets')
  .description('Scan a directory for accidentally committed API keys, tokens and private keys')
  .argument('[path]', 'path to the project directory', '.')
  .action(async (path: string) => {
    await runAndReport('Leaked secrets', () => checkSecrets(resolve(path)));
  });

program
  .command('all')
  .description('Run every check: dependencies + secrets on a local path, and headers on a URL')
  .argument('[path]', 'path to the project directory', '.')
  .option('-u, --url <url>', 'also check HTTP security headers for this URL')
  .action(async (path: string, options: { url?: string }) => {
    const results: CheckResult[] = [];

    results.push(await runCheck('Dependency vulnerabilities', () => checkDependencies(resolve(path))));
    results.push(await runCheck('Leaked secrets', () => checkSecrets(resolve(path))));

    if (options.url) {
      results.push(
        await runCheck(`HTTP security headers (${options.url})`, () => checkHeaders(options.url as string))
      );
    }

    printReport(results);
    process.exitCode = hasBlockingFindings(results) ? 1 : 0;
  });

async function runCheck(checkName: string, fn: () => Promise<CheckResult['findings']>): Promise<CheckResult> {
  try {
    const findings = await fn();
    return { checkName, findings };
  } catch (err) {
    return { checkName, findings: [], error: (err as Error).message };
  }
}

async function runAndReport(checkName: string, fn: () => Promise<CheckResult['findings']>): Promise<void> {
  const result = await runCheck(checkName, fn);
  printReport([result]);
  process.exitCode = hasBlockingFindings([result]) ? 1 : 0;
}

program.parseAsync(process.argv);

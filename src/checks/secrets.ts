import { readFileSync, readdirSync, statSync } from 'fs';
import { join, relative } from 'path';
import { Finding } from '../shared/types';

interface SecretPattern {
  name: string;
  regex: RegExp;
  severity: 'critical' | 'high';
}

/**
 * Each pattern targets a well-known credential FORMAT, not just the
 * word "key" or "secret" (which would flood the report with false
 * positives from variable names and comments). Real secret scanners
 * (gitleaks, truffleHog) work the same way: match the distinctive
 * shape a provider's tokens always have.
 */
const SECRET_PATTERNS: SecretPattern[] = [
  {
    name: 'AWS Access Key ID',
    regex: /\b(AKIA|ASIA)[0-9A-Z]{16}\b/g,
    severity: 'critical',
  },
  {
    name: 'AWS Secret Access Key (assignment)',
    regex: /aws_secret_access_key\s*=\s*['"]?[A-Za-z0-9/+=]{40}['"]?/gi,
    severity: 'critical',
  },
  {
    name: 'GitHub Personal Access Token',
    regex: /\bgh[pousr]_[A-Za-z0-9]{36,255}\b/g,
    severity: 'critical',
  },
  {
    name: 'Slack Token',
    regex: /\bxox[baprs]-[A-Za-z0-9-]{10,72}\b/g,
    severity: 'high',
  },
  {
    name: 'Generic private key block',
    regex: /-----BEGIN (RSA |EC |OPENSSH |DSA |)PRIVATE KEY-----/g,
    severity: 'critical',
  },
  {
    name: 'Stripe API key',
    regex: /\b(sk|rk)_(live|test)_[A-Za-z0-9]{16,247}\b/g,
    severity: 'critical',
  },
  {
    name: 'Google API key',
    regex: /\bAIza[0-9A-Za-z\-_]{35}\b/g,
    severity: 'high',
  },
  {
    name: 'Generic high-entropy secret assignment',
    // Matches patterns like: API_KEY = "a1b2c3d4e5f6...32+chars" — a
    // variable whose name signals a secret, assigned a long opaque
    // string. Deliberately requires BOTH the name hint and a long
    // value, to keep false positives low.
    regex: /\b(api[_-]?key|secret|token|password|passwd)\s*[:=]\s*['"][A-Za-z0-9_\-/+=]{20,}['"]/gi,
    severity: 'high',
  },
];

const IGNORED_DIRS = new Set(['node_modules', '.git', 'dist', 'build', 'coverage', '.next']);
const MAX_FILE_SIZE_BYTES = 2 * 1024 * 1024; // skip anything over 2MB (likely binary/generated)
const TEXT_FILE_EXTENSIONS = new Set([
  '.js', '.ts', '.jsx', '.tsx', '.json', '.env', '.yml', '.yaml',
  '.py', '.rb', '.go', '.java', '.php', '.sh', '.txt', '.md', '.xml',
  '.properties', '.ini', '.cfg', '.toml', '.conf',
]);

/**
 * Pure scanning function: given file content, returns the secrets found
 * in it. Separated from filesystem traversal so it's trivially unit
 * -testable with inline strings, no fixture files needed.
 */
export function scanContentForSecrets(content: string, filePath: string): Finding[] {
  const findings: Finding[] = [];
  const lines = content.split('\n');

  for (const pattern of SECRET_PATTERNS) {
    lines.forEach((line, lineIndex) => {
      // Reset lastIndex since regexes are reused with the /g flag across lines.
      pattern.regex.lastIndex = 0;
      const match = pattern.regex.exec(line);
      if (match) {
        findings.push({
          source: 'secrets',
          severity: pattern.severity,
          title: `Potential ${pattern.name} exposed`,
          detail: `${filePath}:${lineIndex + 1} — matched pattern "${pattern.name}"`,
          recommendation: 'Rotate this credential immediately and move it to an environment variable or secrets manager',
        });
      }
    });
  }

  return findings;
}

function shouldSkipDir(name: string): boolean {
  return IGNORED_DIRS.has(name) || name.startsWith('.');
}

function isTextFile(filePath: string): boolean {
  const ext = filePath.substring(filePath.lastIndexOf('.'));
  return TEXT_FILE_EXTENSIONS.has(ext) || filePath.endsWith('.env');
}

function walkFiles(dir: string, rootDir: string, out: string[]): void {
  const entries = readdirSync(dir, { withFileTypes: true });

  for (const entry of entries) {
    const fullPath = join(dir, entry.name);

    if (entry.isDirectory()) {
      if (!shouldSkipDir(entry.name)) {
        walkFiles(fullPath, rootDir, out);
      }
      continue;
    }

    if (entry.isFile() && isTextFile(entry.name)) {
      const size = statSync(fullPath).size;
      if (size <= MAX_FILE_SIZE_BYTES) {
        out.push(fullPath);
      }
    }
  }
}

export async function checkSecrets(projectPath: string): Promise<Finding[]> {
  const files: string[] = [];
  walkFiles(projectPath, projectPath, files);

  const findings: Finding[] = [];
  for (const filePath of files) {
    const content = readFileSync(filePath, 'utf-8');
    const relativePath = relative(projectPath, filePath);
    findings.push(...scanContentForSecrets(content, relativePath));
  }

  return findings;
}

import { scanContentForSecrets } from '../../src/checks/secrets';

describe('scanContentForSecrets', () => {
  it('detects an AWS access key ID', () => {
    const content = `const key = "AKIAIOSFODNN7EXAMPLE";`;
    const findings = scanContentForSecrets(content, 'config.js');

    expect(findings).toHaveLength(1);
    expect(findings[0].title).toContain('AWS Access Key ID');
    expect(findings[0].severity).toBe('critical');
  });

  it('detects a GitHub personal access token', () => {
    const content = `TOKEN=ghp_${'a'.repeat(36)}`;
    const findings = scanContentForSecrets(content, '.env');

    expect(findings.some((f) => f.title.includes('GitHub'))).toBe(true);
  });

  it('detects a PEM private key block', () => {
    const content = '-----BEGIN RSA PRIVATE KEY-----\nMIIEow...\n-----END RSA PRIVATE KEY-----';
    const findings = scanContentForSecrets(content, 'id_rsa');

    expect(findings.some((f) => f.title.includes('private key'))).toBe(true);
  });

  it('reports the correct line number for a match found deep in a file', () => {
    const content = ['line 1', 'line 2', 'const secret = "AKIAIOSFODNN7EXAMPLE"', 'line 4'].join('\n');
    const findings = scanContentForSecrets(content, 'app.js');

    expect(findings[0].detail).toContain('app.js:3');
  });

  it('does not flag ordinary code that merely mentions the word "key" or "token"', () => {
    const content = `
      // this function validates a user's API key format
      function isValidKeyFormat(key) {
        return key.length > 0;
      }
      const tokenType = 'bearer';
    `;
    const findings = scanContentForSecrets(content, 'utils.js');

    expect(findings).toEqual([]);
  });

  it('detects a generic secret assignment when the value is long enough', () => {
    const content = `API_KEY="thisIsALongOpaqueLookingSecretValue123"`;
    const findings = scanContentForSecrets(content, '.env');

    expect(findings.some((f) => f.title.includes('Generic high-entropy secret'))).toBe(true);
  });

  it('does not flag a short placeholder-like assignment', () => {
    const content = `API_KEY="changeme"`;
    const findings = scanContentForSecrets(content, '.env.example');

    expect(findings).toEqual([]);
  });
});

import { evaluateHeaders } from '../../src/checks/headers';

const URL = 'https://example.com';

describe('evaluateHeaders', () => {
  it('flags every missing security header when none are present', () => {
    const findings = evaluateHeaders({}, URL);

    const titles = findings.map((f) => f.title);
    expect(titles).toContain('Missing header: strict-transport-security');
    expect(titles).toContain('Missing header: content-security-policy');
    expect(titles).toContain('Missing header: x-content-type-options');
    expect(titles).toContain('Missing header: x-frame-options');
  });

  it('reports no findings when all headers are present and correctly configured', () => {
    const findings = evaluateHeaders(
      {
        'strict-transport-security': 'max-age=31536000; includeSubDomains',
        'content-security-policy': "default-src 'self'",
        'x-content-type-options': 'nosniff',
        'x-frame-options': 'DENY',
        'referrer-policy': 'no-referrer',
        'permissions-policy': 'geolocation=()',
      },
      URL
    );

    expect(findings).toEqual([]);
  });

  it('flags an HSTS header with too-short max-age as a weak configuration, not a missing one', () => {
    const findings = evaluateHeaders(
      {
        'strict-transport-security': 'max-age=60',
        'content-security-policy': "default-src 'self'",
        'x-content-type-options': 'nosniff',
        'x-frame-options': 'DENY',
      },
      URL
    );

    const hstsFinding = findings.find((f) => f.detail.includes('max-age'));
    expect(hstsFinding).toBeDefined();
    expect(hstsFinding?.title).toContain('Weak header configuration');
  });

  it('flags a cookie missing Secure/HttpOnly/SameSite flags', () => {
    const findings = evaluateHeaders(
      {
        'strict-transport-security': 'max-age=31536000',
        'content-security-policy': "default-src 'self'",
        'x-content-type-options': 'nosniff',
        'x-frame-options': 'DENY',
        'set-cookie': 'sessionId=abc123; Path=/',
      },
      URL
    );

    const cookieFinding = findings.find((f) => f.title === 'Cookie missing security flags');
    expect(cookieFinding).toBeDefined();
    expect(cookieFinding?.detail).toContain('Secure');
    expect(cookieFinding?.detail).toContain('HttpOnly');
    expect(cookieFinding?.detail).toContain('SameSite');
  });

  it('does not flag a cookie that already has all three security flags', () => {
    const findings = evaluateHeaders(
      {
        'strict-transport-security': 'max-age=31536000',
        'content-security-policy': "default-src 'self'",
        'x-content-type-options': 'nosniff',
        'x-frame-options': 'DENY',
        'set-cookie': 'sessionId=abc123; Secure; HttpOnly; SameSite=Strict',
      },
      URL
    );

    expect(findings.find((f) => f.title === 'Cookie missing security flags')).toBeUndefined();
  });
});

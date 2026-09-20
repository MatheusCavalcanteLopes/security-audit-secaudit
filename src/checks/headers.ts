import { Finding, Severity } from '../shared/types';

interface SecurityHeaderRule {
  header: string;
  severity: Severity;
  description: string;
  /** Optional: validates the header's VALUE, not just its presence */
  validate?: (value: string) => string | null; // returns a problem message, or null if OK
}

/**
 * Each rule encodes one well-known HTTP security header, why it matters,
 * and (when relevant) what a weak configuration looks like — not just
 * "present vs absent". This is the kind of checklist a security
 * engineer keeps in their head; encoding it in code is what makes the
 * tool useful instead of a single hardcoded check.
 */
const SECURITY_HEADER_RULES: SecurityHeaderRule[] = [
  {
    header: 'strict-transport-security',
    severity: 'high',
    description:
      'HSTS forces browsers to only connect over HTTPS, preventing downgrade and SSL-stripping attacks.',
    validate: (value) => {
      const maxAgeMatch = value.match(/max-age=(\d+)/i);
      const maxAge = maxAgeMatch ? parseInt(maxAgeMatch[1], 10) : 0;
      // 6 months is a commonly recommended floor for HSTS max-age.
      if (maxAge < 15552000) {
        return `max-age is only ${maxAge}s (recommended: 15552000s / 180 days or more)`;
      }
      return null;
    },
  },
  {
    header: 'content-security-policy',
    severity: 'high',
    description:
      'CSP restricts which sources of scripts/styles/images the page may load, mitigating XSS and data injection attacks.',
  },
  {
    header: 'x-content-type-options',
    severity: 'medium',
    description:
      'Prevents browsers from MIME-sniffing a response away from its declared Content-Type, which can be abused to execute disguised scripts.',
    validate: (value) => (value.toLowerCase() !== 'nosniff' ? `unexpected value "${value}"` : null),
  },
  {
    header: 'x-frame-options',
    severity: 'medium',
    description: 'Prevents the page from being embedded in an iframe on another site (clickjacking).',
  },
  {
    header: 'referrer-policy',
    severity: 'low',
    description: 'Controls how much referrer information is leaked when users navigate away from the page.',
  },
  {
    header: 'permissions-policy',
    severity: 'low',
    description: 'Restricts which browser features (camera, geolocation, etc.) the page may use.',
  },
];

/**
 * Pure function: given a Headers-like map, returns the list of security
 * findings. Kept separate from the actual network fetch so it can be
 * unit-tested with a hand-built header set, no HTTP request needed.
 */
export function evaluateHeaders(headers: Record<string, string>, targetUrl: string): Finding[] {
  const normalized: Record<string, string> = {};
  for (const [key, value] of Object.entries(headers)) {
    normalized[key.toLowerCase()] = value;
  }

  const findings: Finding[] = [];

  for (const rule of SECURITY_HEADER_RULES) {
    const value = normalized[rule.header];

    if (value === undefined) {
      findings.push({
        source: 'headers',
        severity: rule.severity,
        title: `Missing header: ${rule.header}`,
        detail: `${targetUrl} does not send a "${rule.header}" header. ${rule.description}`,
      });
      continue;
    }

    if (rule.validate) {
      const problem = rule.validate(value);
      if (problem) {
        findings.push({
          source: 'headers',
          severity: rule.severity,
          title: `Weak header configuration: ${rule.header}`,
          detail: `${targetUrl}: ${problem}`,
        });
      }
    }
  }

  // A cookie without Secure/HttpOnly/SameSite is a separate, high-value check.
  const setCookie = normalized['set-cookie'];
  if (setCookie) {
    const missingFlags: string[] = [];
    if (!/secure/i.test(setCookie)) missingFlags.push('Secure');
    if (!/httponly/i.test(setCookie)) missingFlags.push('HttpOnly');
    if (!/samesite/i.test(setCookie)) missingFlags.push('SameSite');

    if (missingFlags.length > 0) {
      findings.push({
        source: 'headers',
        severity: 'high',
        title: 'Cookie missing security flags',
        detail: `${targetUrl} sets a cookie without: ${missingFlags.join(', ')}`,
        recommendation: 'Add the missing flags to prevent XSS/CSRF-based cookie theft',
      });
    }
  }

  return findings;
}

export async function checkHeaders(targetUrl: string): Promise<Finding[]> {
  let response: Response;
  try {
    response = await fetch(targetUrl, { method: 'GET', redirect: 'follow' });
  } catch (err) {
    throw new Error(`Could not reach ${targetUrl}: ${(err as Error).message}`);
  }

  const headers: Record<string, string> = {};
  response.headers.forEach((value, key) => {
    headers[key] = value;
  });

  return evaluateHeaders(headers, targetUrl);
}

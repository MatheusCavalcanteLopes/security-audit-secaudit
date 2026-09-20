import { parseLockfileDependencies } from '../../src/checks/dependencies';

describe('parseLockfileDependencies', () => {
  it('parses npm lockfile v3 format (the "packages" key)', () => {
    const lockfile = JSON.stringify({
      lockfileVersion: 3,
      packages: {
        '': { name: 'my-app', version: '1.0.0' },
        'node_modules/express': { version: '4.21.0' },
        'node_modules/express/node_modules/qs': { version: '6.13.0' },
      },
    });

    const result = parseLockfileDependencies(lockfile);

    expect(result).toContainEqual({ name: 'express', version: '4.21.0' });
    expect(result).toContainEqual({ name: 'qs', version: '6.13.0' });
    // the root project entry ("") must NOT be treated as a dependency
    expect(result.find((p) => p.name === 'my-app')).toBeUndefined();
  });

  it('parses npm lockfile v1 format (the "dependencies" key)', () => {
    const lockfile = JSON.stringify({
      lockfileVersion: 1,
      dependencies: {
        lodash: { version: '4.17.21' },
      },
    });

    const result = parseLockfileDependencies(lockfile);

    expect(result).toEqual([{ name: 'lodash', version: '4.17.21' }]);
  });

  it('deduplicates identical name+version pairs', () => {
    const lockfile = JSON.stringify({
      packages: {
        'node_modules/foo': { version: '1.0.0' },
        'node_modules/bar/node_modules/foo': { version: '1.0.0' },
      },
    });

    const result = parseLockfileDependencies(lockfile);
    expect(result).toHaveLength(1);
  });

  it('returns an empty array when the lockfile has no recognizable dependency data', () => {
    const result = parseLockfileDependencies(JSON.stringify({ lockfileVersion: 3 }));
    expect(result).toEqual([]);
  });
});

import { describe, expect, it } from 'vitest';
import { groupCodeLocations } from '../src/features/code-map/CodeMap';
import type { CodeLocation } from '../src/domain/index';

function location(overrides: Partial<CodeLocation> = {}): CodeLocation {
  return { key: 'location', runId: 'audit-a', scopeId: 'scope-a', sourceView: 'base', repository: 'web',
    file: 'web/controllers/account.ts', line: 10, endLine: 14, scope: 'readAccount', findingKeys: ['finding-a'],
    componentKeys: ['component-a'], roles: ['root_cause'], explanations: ['Recorded authority decision'], ...overrides };
}

describe('cited code map file grouping', () => {
  it('groups only the same file within one execution, assessment and source view', () => {
    const files = groupCodeLocations([
      location(), location({ key: 'another', line: 20, roles: ['repair'] }),
      location({ key: 'different-run', runId: 'audit-b' }),
      location({ key: 'different-scope', scopeId: 'scope-b' }),
      location({ key: 'different-view', sourceView: 'derived' }),
    ]);
    expect(files).toHaveLength(4);
    expect(files.find(file => file.runId === 'audit-a' && file.scopeId === 'scope-a' && file.sourceView === 'base')?.locations).toHaveLength(2);
    expect(files.every(file => file.file === 'web/controllers/account.ts')).toBe(true);
  });

  it('preserves unknown scope and repository metadata without borrowing another record', () => {
    const files = groupCodeLocations([location({ repository: null, scopeId: null, sourceView: null })]);
    expect(files[0].repository).toBe('Repository not recorded');
    expect(files[0].scopeId).toBeNull();
    expect(files[0].sourceView).toBeNull();
    expect(files[0].locations[0].findingKeys).toEqual(['finding-a']);
  });
});

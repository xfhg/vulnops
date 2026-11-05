import { describe, expect, it } from 'vitest';
import { connectionContext } from '../src/features/entrypoint-explorer/connections';

describe('recorded graph connection context', () => {
  const nodes = ['entry', 'finding-a', 'finding-b', 'other-entry'];
  const edges = [{ id: 'a', source: 'entry', target: 'finding-a' }, { id: 'b', source: 'entry', target: 'finding-b' }, { id: 'other', source: 'other-entry', target: 'finding-b' }];
  it('highlights only the selected entrypoint and its actual one-hop associations', () => {
    const result = connectionContext(nodes, edges, 'entry');
    expect([...result.nodes]).toEqual(['entry', 'finding-a', 'finding-b']);
    expect([...result.edges]).toEqual(['a', 'b']);
  });
  it('keeps an edge selection restricted to its own endpoints', () => {
    const result = connectionContext(nodes, edges, 'b');
    expect([...result.nodes]).toEqual(['entry', 'finding-b']);
    expect([...result.edges]).toEqual(['b']);
  });
  it('does not invent relationships for missing selections or dangling endpoints', () => {
    expect(connectionContext(nodes, edges, 'missing').nodes.size).toBe(0);
    const result = connectionContext(nodes, [...edges, { id: 'dangling', source: 'entry', target: 'missing' }], 'entry');
    expect(result.nodes.has('missing')).toBe(false); expect(result.edges.has('dangling')).toBe(false);
  });
});

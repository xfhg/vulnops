// @vitest-environment jsdom
import { afterEach, describe, expect, it, vi } from 'vitest';
import { cleanup, render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import '@testing-library/jest-dom/vitest';
import { buildCodeIndex, normalizeWorkspace } from '../src/domain';
import CodeMap from '../src/features/code-map/CodeMap';
import { CodeInspector } from '../src/features/code-map/CodeInspector';
import { groupCodeLocations, projectCodeFile, type CodeGraphNode } from '../src/features/code-map/projection';
import { makeFinding, makePublication } from './fixtures/bundles';

vi.mock('../src/features/code-map/CodeCanvas', () => ({ CodeCanvas: ({ graphNodes, onOpen }: { graphNodes: CodeGraphNode[]; onOpen: (node: CodeGraphNode) => void }) => <div aria-label="Synthetic graph canvas">{graphNodes.filter(node => node.kind === 'location').map(node => <button key={node.id} onClick={() => onOpen(node)}>Open graph {node.label}</button>)}</div> }));
afterEach(cleanup);

describe('code relationship interactions', () => {
  it('selects a useful file by default and opens the exact selected range with its owner', async () => {
    const raw = makeFinding();
    raw.remediation!.actions[0].evidence_refs!.unshift('storefront/src/orders.ts:10');
    const findings = normalizeWorkspace([makePublication({ runId: 'code-owner', findings: [raw] })]).findings;
    const user = userEvent.setup(), onEvidence = vi.fn();
    render(<CodeMap findings={findings} onFinding={vi.fn()} onEvidence={onEvidence}/>);
    expect(screen.getByRole('heading', { name: 'storefront/src/orders.ts' })).toBeVisible();
    await user.click(screen.getByRole('button', { name: 'Open graph Line 42' }));
    expect(onEvidence).toHaveBeenCalledWith('storefront/src/orders.ts:42', 'code-owner');
    await user.click(screen.getByRole('button', { name: 'Locations' }));
    expect(screen.queryByLabelText('Synthetic graph canvas')).not.toBeInTheDocument();
    expect(screen.getByRole('heading', { name: /Locations and repair points/ })).toBeVisible();
  });

  it('preserves explicit unavailable file selection instead of silently selecting a different file', () => {
    const findings = normalizeWorkspace([makePublication()]).findings;
    render(<CodeMap findings={findings} selected="unknown-file" onFinding={vi.fn()}/>);
    expect(screen.getByRole('heading', { name: 'Selected file unavailable' })).toBeVisible();
    expect(screen.queryByLabelText('Synthetic graph canvas')).not.toBeInTheDocument();
  });

  it('keeps typed evidence ownership and unresolved repair targets literal in the inspector', async () => {
    const raw = makeFinding();
    const reference = { execution_id: 'baseline-owner', artifact_ref: 'final-verification/results/F-4.json', selector: '/review' };
    raw.remediation!.actions[0].evidence_refs = [reference];
    raw.remediation!.actions[0].breaks_steps = ['step-2', 'missing-step'];
    raw.remediation!.actions[0].component_ids = ['missing-component'];
    const findings = normalizeWorkspace([makePublication({ runId: 'code-owner', findings: [raw] })]).findings;
    const file = groupCodeLocations(buildCodeIndex(findings))[0];
    const graph = projectCodeFile(file, findings);
    const repair = graph.nodes.find(node => node.kind === 'repair')!;
    const user = userEvent.setup(), onEvidence = vi.fn(), onFinding = vi.fn();
    render(<CodeInspector graph={graph} selected={repair.id} onEvidence={onEvidence} onFinding={onFinding}/>);
    await user.click(screen.getByRole('button', { name: 'final-verification/results/F-4.json · /review · baseline-owner' }));
    expect(onEvidence).toHaveBeenLastCalledWith(reference, 'code-owner');
    expect(onEvidence.mock.calls[0][0]).toBe(reference);
    expect(screen.getByText('Target step unavailable in this finding')).toBeVisible();
    expect(screen.getByText('Component unavailable in this finding')).toBeVisible();
    expect(screen.getByText(raw.exploitation!.steps[1].action)).toBeVisible();
    expect(screen.queryByRole('button', { name: /missing-step|missing-component/ })).not.toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Open finding' }));
    expect(onFinding).toHaveBeenLastCalledWith(findings[0].key);
  });
});

import { buildCodeIndex, filterFindings, type FindingRecord } from '../domain';
import type { WorkspaceResponse } from '../domain/sources';
import type { WorkspaceDataSource } from '../data/types';
import { groupCodeLocations } from '../features/code-map/projection';
import { buildRepairEntries, projectRepair } from '../features/remediation/model';
import { projectFinding, type GraphMode } from '../features/attack-explorer/projection';
import { connectedRecords } from '../features/attack-explorer/relationships';
import { buildCompositionOverview, buildEntrypointIndex, overviewChainId, overviewFindingId, overviewUnassignedId } from '../features/entrypoint-explorer/model';

const views = ['overview', 'findings', 'attacks', 'code', 'remediation', 'assessment'];
const panels = ['summary', 'reproduce', 'repair', 'verify', 'evidence', 'graph'];
const modes: GraphMode[] = ['procedure', 'trace', 'composition'];
function graphSelectionExists(finding: FindingRecord, mode: GraphMode, selected: string, repair = ''): boolean {
  const graph = projectFinding(finding, mode, repair);
  const connected = connectedRecords(finding, mode, graph, selected);
  return [...graph.nodes, ...graph.edges, ...connected.nodes, ...connected.edges].some(item => item.id === selected);
}
function detailExists(finding: FindingRecord, value: string, panel: string, repair: string): boolean {
  const raw = finding.raw;
  const targets = panel === 'verify' ? (raw.remediation?.verification_checks ?? []).map(check => JSON.stringify(['check', check.id]))
    : panel === 'reproduce' ? [...(raw.exploitation?.steps ?? []).map(step => JSON.stringify(['step', step.id])), ...(raw.technical_examples ?? []).map(example => JSON.stringify(['example', example.id]))]
    : panel === 'repair' ? (raw.remediation?.actions ?? []).filter(action => !repair || repair === action.id)
      .flatMap(action => (action.locations ?? []).map((_, index) => JSON.stringify(['repair-location', action.id, index]))) : [];
  return targets.includes(value);
}

/**
 * Check the exact first-import destination using the same qualified projection
 * IDs as each view. No local-ID fallback, speculative owner or file matching.
 * Ordinary restoration leaves the existing route alone; this only decides
 * whether a pending link can be resumed when an empty browser first imports.
 */
export async function matchesBrowserDestination(params: URLSearchParams, workspace: WorkspaceResponse, source: WorkspaceDataSource, signal?: AbortSignal): Promise<boolean> {
  const value = (name: string) => params.get(name) ?? '';
  const view = value('view') || 'overview', run = value('run'), repository = value('repo'), findingKey = value('finding');
  if (!views.includes(view) || run && !workspace.assessments.some(item => item.id === run)) return false;
  if (repository && !workspace.findings.some(item => item.repositories.includes(repository))) return false;
  if (view === 'remediation' && value('repairView') && !['brief', 'map', 'records'].includes(value('repairView'))) return false;
  if (view === 'attacks' && value('entryMode') && !['entrypoints', 'composed'].includes(value('entryMode'))) return false;
  const generation = workspace.generation;
  const scoped = (findings: FindingRecord[]) => filterFindings(findings, { assessment: run, repository });
  async function details(): Promise<FindingRecord[]> {
    const findings: FindingRecord[] = [];
    for (let offset = 0; offset < workspace.findings.length;) {
      if (signal?.aborted) return [];
      const page = await source.page(offset, 250, generation, signal);
      if (!page.items.length || page.total !== workspace.findings.length) return [];
      findings.push(...page.items); offset += page.items.length;
    }
    return signal?.aborted ? [] : scoped(findings);
  }
  async function repairMatches(findings: FindingRecord[], owner?: string): Promise<boolean> {
    if (value('repairView') && !['brief', 'map', 'records'].includes(value('repairView'))) return false;
    const requested = value('repairAction'), selected = value('repairSelected');
    if (!requested) return !selected;
    const entry = buildRepairEntries(findings).find(item => item.key === requested);
    if (!entry || owner && entry.finding.key !== owner) return false;
    if (!selected) return true;
    const graph = projectRepair(entry);
    return [...graph.nodes, ...graph.edges].some(item => item.id === selected);
  }
  try {
    if (signal?.aborted) return false;
    if (findingKey) {
      const summary = workspace.findings.find(item => item.key === findingKey);
      if (!summary || summary.conflicted || run && summary.runId !== run && !summary.historicalIn.includes(run)) return false;
      const finding = await source.finding(findingKey, generation, signal);
      const panel = value('panel') || (value('selected') || ['trace', 'composition'].includes(value('mode')) ? 'graph' : 'summary');
      const mode = value('mode') || 'procedure';
      if (!panels.includes(panel) || !modes.includes(mode as GraphMode)) return false;
      if (value('repair') && !finding.raw.remediation?.actions?.some(action => action.id === value('repair'))) return false;
      if (value('detailRecord') && !detailExists(finding, value('detailRecord'), panel, value('repair'))) return false;
      if (value('selected') && (panel !== 'graph' || !graphSelectionExists(finding, mode as GraphMode, value('selected'), value('repair')))) return false;
      if (view === 'remediation' && !await repairMatches(scoped([finding]), findingKey)) return false;
      return !signal?.aborted;
    }
    if (view === 'code' && value('location')) {
      const files = groupCodeLocations(buildCodeIndex(await details()));
      return files.some(file => file.key === value('location'));
    }
    if (view === 'remediation' && (value('repairAction') || value('repairSelected'))) return repairMatches(await details());
    if (view === 'attacks' && value('entrySelected')) {
      const findings = await details(), selected = value('entrySelected');
      if (value('entryMode') === 'composed') {
        const overview = buildCompositionOverview(findings);
        return [...overview.nodes, ...overview.edges].some(item => item.id === selected)
          || overview.chains.some(({ finding }) => overviewChainId(finding.key) === selected || graphSelectionExists(finding, 'composition', selected));
      }
      if (value('entryMode') && value('entryMode') !== 'entrypoints') return false;
      const index = buildEntrypointIndex(findings);
      return index.clusters.some(item => item.id === selected) || index.associations.some(item => item.id === selected)
        || index.findings.some(item => overviewFindingId(item.key) === selected) || selected === overviewUnassignedId && index.unassigned.length > 0;
    }
    // A run-qualified destination is meaningful without a selected child. An
    // orphan child selector must not silently open a default record instead.
    if (['location', 'repairAction', 'repairSelected', 'entrySelected', 'selected', 'repair', 'detailRecord'].some(key => value(key))) return false;
    return Boolean(run) && !signal?.aborted;
  } catch { return false; }
}

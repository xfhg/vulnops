import { expect, test, type Page } from '@playwright/test';
import type { FindingSummary } from '../../src/domain/types';
import type { WorkspaceResponse } from '../../src/domain/sources';

const metricNames = {
  confirmed: 'Explore confirmed outcomes',
  highImpact: 'Explore high and critical outcomes',
  chains: 'Explore recorded chains',
  environment: 'Explore environment-required outcomes',
} as const;

async function workspace(page: Page): Promise<WorkspaceResponse> {
  const response = await page.request.get('/api/workspace');
  expect(response.ok()).toBe(true);
  return response.json();
}
function assessed(findings: FindingSummary[]): FindingSummary[] {
  return [...new Map(findings.filter(finding => finding.origin === 'assessed' && !finding.conflicted).map(finding => [finding.key, finding])).values()];
}
async function expectMetrics(page: Page, findings: FindingSummary[]) {
  const own = assessed(findings), confirmed = own.filter(finding => finding.cohort === 'confirmed');
  const counts = {
    confirmed: confirmed.length,
    highImpact: confirmed.filter(finding => finding.severity === 'critical' || finding.severity === 'high').length,
    chains: confirmed.filter(finding => finding.kind === 'chain').length,
    environment: own.filter(finding => finding.cohort === 'needs_environment').length,
  };
  for (const key of Object.keys(metricNames) as Array<keyof typeof metricNames>) {
    await expect(page.getByRole('button', { name: metricNames[key], exact: true }).locator('.overview-metric-value')).toHaveText(String(counts[key]));
  }
}
async function overview(page: Page, query = '') {
  await page.goto('/?view=overview' + query);
  await expect(page.getByRole('heading', { level: 1, name: 'Assessment overview', exact: true })).toBeVisible();
}
function query(page: Page) { return new URL(page.url()).searchParams; }

test('Overview KPIs use assessed records and high-impact drilldown replaces incompatible filters', async ({ page }) => {
  const snapshot = await workspace(page);
  await overview(page, '&q=stale-query&status=rejected&severity=low&kind=not-a-kind&classification=baseline_correction&origin=historical');
  await expectMetrics(page, snapshot.findings);
  const handoff = page.getByRole('region', { name: 'Developer handoff', exact: true });
  const confirmedActions = assessed(snapshot.findings).filter(finding => finding.cohort === 'confirmed').reduce((count, finding) => count + finding.repairCount, 0);
  await expect(handoff.locator('.overview-action-records strong')).toHaveText(String(confirmedActions));
  await expect(handoff).toContainText('Recommendations, not completed fixes.');
  await expect(page.getByRole('button', { name: 'Settings', exact: true })).toBeVisible();
  await page.getByRole('button', { name: metricNames.highImpact, exact: true }).click();
  await expect(page.getByRole('heading', { name: 'Findings, in context.', exact: true })).toBeVisible();
  expect(query(page).get('view')).toBe('findings');
  expect(query(page).get('severity')).toBe('critical,high');
  expect(query(page).get('status')).toBe('confirmed');
  expect(query(page).get('origin')).toBe('assessed');
  for (const name of ['q', 'kind', 'classification', 'finding', 'repair', 'selected']) expect(query(page).has(name)).toBe(false);
  const expected = assessed(snapshot.findings).filter(finding => finding.cohort === 'confirmed' && ['critical', 'high'].includes(finding.severity));
  await expect(page.getByText(`${expected.length} matching ${expected.length === 1 ? 'finding' : 'findings'}`, { exact: true })).toBeVisible();
  const rows = page.locator('.findings-table tbody tr');
  await expect(rows).toHaveCount(expected.length);
  for (const finding of expected) await expect(page.getByRole('button', { name: `Open ${finding.id}`, exact: true })).toBeVisible();
  await page.getByLabel('Filter disposition', { exact: true }).selectOption('historical');
  expect(query(page).has('origin')).toBe(false);
  const historical = snapshot.findings.filter(finding => (finding.origin === 'historical' || finding.historicalIn.length > 0) && ['critical', 'high'].includes(finding.severity));
  await expect(page.getByText(`${historical.length} matching ${historical.length === 1 ? 'finding' : 'findings'}`, { exact: true })).toBeVisible();
  await expect(rows).toHaveCount(historical.length);
  for (const finding of historical) await expect(page.getByRole('button', { name: `Open ${finding.id}`, exact: true })).toBeVisible();
});

test('repository and assessment scopes keep KPI counts and drilldowns consistent', async ({ page }) => {
  const snapshot = await workspace(page);
  const ordinary = snapshot.assessments.find(assessment => assessment.kind === 'audit')!;
  const repository = assessed(snapshot.findings).find(finding => finding.runId === ordinary.id && finding.repositories.length)?.repositories[0]!;
  await overview(page);
  await page.getByLabel('Select assessment', { exact: true }).selectOption(ordinary.id);
  await page.getByLabel('Filter repository', { exact: true }).selectOption(repository);
  const scoped = snapshot.findings.filter(finding => finding.runId === ordinary.id && finding.repositories.includes(repository));
  await expectMetrics(page, scoped);
  const exposure = page.getByRole('region', { name: 'Confirmed outcomes by repository', exact: true });
  await expect(exposure).toContainText(repository);
  await exposure.getByRole('button', { name: `Explore confirmed outcomes in ${repository}`, exact: true }).click();
  expect(query(page).get('run')).toBe(ordinary.id); expect(query(page).get('repo')).toBe(repository);
  expect(query(page).get('status')).toBe('confirmed'); expect(query(page).get('origin')).toBe('assessed');
  const expected = assessed(scoped).filter(finding => finding.cohort === 'confirmed');
  await expect(page.getByText(`${expected.length} matching ${expected.length === 1 ? 'finding' : 'findings'}`, { exact: true })).toBeVisible();

  await overview(page, `&run=${encodeURIComponent(ordinary.id)}&repo=${encodeURIComponent(repository)}&severity=low&classification=new_root`);
  await page.getByRole('button', { name: metricNames.environment, exact: true }).click();
  expect(query(page).get('status')).toBe('needs_environment'); expect(query(page).get('run')).toBe(ordinary.id);
  expect(query(page).get('repo')).toBe(repository); expect(query(page).has('severity')).toBe(false); expect(query(page).has('classification')).toBe(false);
});

test('priority ordering and Advantage contribution preserve explicit assessed cohorts', async ({ page }) => {
  const snapshot = await workspace(page);
  await overview(page);
  await page.getByRole('tab', { name: 'All confirmed', exact: true }).click();
  const priority = page.getByRole('table', { name: 'Priority findings', exact: true });
  const rank = { critical: 0, high: 1, medium: 2, low: 3, info: 4, unknown: 5 };
  const natural = new Intl.Collator('en', { numeric: true });
  const expected = assessed(snapshot.findings).filter(finding => finding.cohort === 'confirmed').sort((a, b) => rank[a.severity] - rank[b.severity] || natural.compare(a.id, b.id) || natural.compare(a.runId, b.runId));
  await expect(priority.locator('.priority-row')).toHaveCount(Math.min(expected.length, 5));
  expect(await priority.locator('.priority-row').evaluateAll(rows => rows.map(row => row.getAttribute('data-finding-key')))).toEqual(expected.slice(0, 5).map(finding => finding.key));
  await page.getByRole('tab', { name: 'Needs environment', exact: true }).click();
  const needsEnvironment = assessed(snapshot.findings).filter(finding => finding.cohort === 'needs_environment');
  await expect(priority.locator('.priority-row')).toHaveCount(Math.min(needsEnvironment.length, 5));
  expect(await priority.locator('.priority-row').evaluateAll(rows => rows.map(row => row.getAttribute('data-finding-key')))).toEqual(needsEnvironment.slice(0, 5).map(finding => finding.key));

  const advantage = snapshot.assessments.find(assessment => assessment.kind === 'advantage')!;
  await page.getByLabel('Select assessment', { exact: true }).selectOption(advantage.id);
  await expectMetrics(page, snapshot.findings.filter(finding => finding.runId === advantage.id));
  const contribution = page.getByRole('region', { name: 'Advantage contribution', exact: true });
  for (const label of ['New roots', 'New chains', 'Impact expansions', 'Revalidations', 'Corrections']) await expect(contribution.getByText(label, { exact: true })).toBeVisible();
  await expect(page.getByRole('region', { name: 'Report context', exact: true })).toContainText(advantage.id);
  // The linked ordinary historical records remain outside Advantage's own KPIs.
  const own = assessed(snapshot.findings).filter(finding => finding.runId === advantage.id && finding.cohort === 'confirmed');
  for (const [classification, label] of [['new_root', 'new roots'], ['new_chain', 'new chains'], ['impact_expansion', 'impact expansions'], ['baseline_revalidation', 'revalidations'], ['baseline_correction', 'corrections']] as const) {
    await expect(contribution.getByRole('button', { name: `Explore Advantage ${label}`, exact: true }).locator('strong')).toHaveText(String(own.filter(finding => finding.classification === classification).length));
  }
  const additions = own.filter(finding => ['new_root', 'new_chain', 'impact_expansion'].includes(finding.classification ?? '')).length;
  await expect(contribution.locator('.overview-added-total')).toHaveText(`${additions} added ${additions === 1 ? 'outcome' : 'outcomes'}`);
  expect(advantage.historicalFindingKeys.length).toBeGreaterThan(0);
  await expect(page.getByRole('button', { name: metricNames.confirmed, exact: true }).locator('.overview-metric-value')).toHaveText(String(own.length));
});

test('missing repository attribution stays visible without creating an invented repository filter', async ({ page }) => {
  // A browser-only synthetic response exercises a sparse review record. The
  // shared report folders and server workspace remain untouched.
  await page.route('**/api/workspace', async route => {
    const response = await route.fetch(); const snapshot: WorkspaceResponse = await response.json();
    const ordinary = snapshot.assessments.find(assessment => assessment.kind === 'audit')!;
    const base = snapshot.findings.find(finding => finding.runId === ordinary.id)!;
    snapshot.findings.push({ ...base, key: JSON.stringify(['finding', ordinary.id, 'F-UNKNOWN-REVIEW']), id: 'F-UNKNOWN-REVIEW', title: 'Synthetic review without repository attribution',
      cohort: 'unconfirmed', verdict: null, status: null, severity: 'unknown', repositories: [], components: [], scope: null, scopeId: null, sourceView: null,
      verificationLevel: null, hasDossier: false, repairCount: 0, stepCount: 0, traceCount: 0, historicalIn: [] });
    await route.fulfill({ response, json: snapshot });
  });
  await overview(page, '&repo=storefront');
  const reviewAttribution = page.getByRole('button', { name: 'Review repository attribution', exact: true });
  await expect(reviewAttribution).toBeVisible();
  await expect(page.locator('.assessment-overview')).toContainText(/1.*review record.*repository/i);
  await reviewAttribution.click();
  expect(query(page).get('view')).toBe('assessment');
  expect(query(page).get('repo')).not.toBe('unknown');
  expect(query(page).get('repo')).not.toBe('Repository unknown');
});

for (const theme of ['light', 'dark'] as const) {
  for (const size of ['desktop', 'mobile'] as const) {
    test(`Overview ${theme} ${size} supports keyboard activation and contained layout`, async ({ page }) => {
      const errors: string[] = [], external: string[] = [];
      page.on('pageerror', error => errors.push(error.message));
      await page.route('**/*', route => {
        if (new URL(route.request().url()).hostname !== '127.0.0.1') { external.push(route.request().url()); return route.abort(); }
        return route.continue();
      });
      await page.addInitScript(value => localStorage.setItem('stake-theme', value), theme);
      await page.setViewportSize(size === 'mobile' ? { width: 390, height: 844 } : { width: 1440, height: 1000 });
      await page.emulateMedia({ reducedMotion: 'reduce' });
      await overview(page);
      if (theme === 'dark') await expect(page.locator('html')).toHaveClass('dark');
      else await expect(page.locator('html')).not.toHaveClass('dark');
      await page.keyboard.press('Tab');
      await expect(page.getByRole('link', { name: 'Skip to content', exact: true })).toBeFocused();
      await page.keyboard.press('Enter'); await expect(page.locator('#main')).toBeFocused();
      const card = page.getByRole('button', { name: metricNames.chains, exact: true });
      await card.focus(); await expect(card).toBeFocused();
      await page.keyboard.press('Enter');
      await expect(page.getByRole('heading', { name: 'Findings, in context.', exact: true })).toBeVisible();
      expect(query(page).get('kind')).toBe('chain'); expect(query(page).get('status')).toBe('confirmed');
      await overview(page);
      await expect(page.getByRole('button', { name: 'Settings', exact: true })).toBeVisible();
      await expect(page.getByRole('region', { name: 'Developer handoff', exact: true })).toBeVisible();
      expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);
      for (const name of Object.values(metricNames)) {
        const bounds = await page.getByRole('button', { name, exact: true }).boundingBox();
        expect(bounds).not.toBeNull(); expect(bounds!.x).toBeGreaterThanOrEqual(0);
        expect(bounds!.x + bounds!.width).toBeLessThanOrEqual((size === 'mobile' ? 390 : 1440) + 1);
      }
      await page.evaluate(() => document.fonts.ready);
      await page.screenshot({ path: `/private/tmp/atstake-overview-modern-${theme}-${size}.png`, fullPage: true, animations: 'disabled' });
      expect(errors).toEqual([]); expect(external).toEqual([]);
    });
  }
}

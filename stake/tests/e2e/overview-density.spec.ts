import { expect, test, type Locator, type Page } from '@playwright/test';
import type { FindingSummary, Severity } from '../../src/domain/types';
import type { WorkspaceResponse } from '../../src/domain/sources';

const repositories = [
  'synthetic-commerce/merchant-onboarding-and-cross-region-payment-authorization-service',
  'synthetic-commerce/customer-account-recovery-and-identity-verification-service',
  'synthetic-commerce/warehouse-fulfilment-and-third-party-shipping-integration-service',
  'synthetic-commerce/subscription-renewal-and-invoice-reconciliation-service',
  'synthetic-commerce/product-catalogue-and-regional-pricing-administration-service',
  'synthetic-commerce/partner-notification-and-webhook-delivery-management-service',
  'synthetic-commerce/support-case-attachments-and-customer-export-management-service',
];
const severities: Severity[] = ['critical', 'high', 'medium', 'low'];
const regionNames = {
  priority: 'Priority findings',
  repositories: 'Confirmed outcomes by repository',
  context: 'Report context',
  handoff: 'Developer handoff',
  advantage: 'Advantage contribution',
} as const;

/** Only the browser response changes. The paired server fixtures and their
 * generation stay intact, so this test cannot affect another browser session. */
async function installDenseOverview(page: Page) {
  await page.route('**/api/workspace', async route => {
    const response = await route.fetch();
    const snapshot: WorkspaceResponse = await response.json();
    const ordinary = snapshot.assessments.find(assessment => assessment.kind === 'audit')!;
    const advantage = snapshot.assessments.find(assessment => assessment.kind === 'advantage')!;
    const fixtures: FindingSummary[] = repositories.flatMap((repository, repositoryIndex) => {
      const owner = repositoryIndex < 5 ? ordinary : advantage;
      const base = snapshot.findings.find(finding => finding.runId === owner.id && finding.origin === 'assessed')!;
      return severities.map((severity, severityIndex) => {
        const id = `DENSE-${repositoryIndex + 1}-${severityIndex + 1}`;
        return {
          ...base, key: JSON.stringify(['finding', owner.id, id]), id,
          title: `Synthetic ${severity} access boundary in service ${repositoryIndex + 1}`,
          impact: 'Synthetic fixture: a recorded access boundary has a bounded effect.',
          attackSummary: 'Synthetic report data for Overview layout coverage.',
          severity, cohort: 'confirmed', origin: 'assessed', verdict: 'confirmed', status: 'confirmed',
          kind: severityIndex === 1 ? 'chain' : 'root',
          classification: owner.kind === 'advantage'
            ? (['new_root', 'new_chain', 'impact_expansion', 'baseline_revalidation'] as const)[severityIndex]
            : null,
          repositories: [repository], components: [],
          scope: base.scope ? { ...base.scope, repositories: [{ name: repository, path: repository }] } : null,
          hasDossier: true, repairCount: severityIndex === 3 ? 0 : 2,
          stepCount: 3, traceCount: 3, verificationLevel: 'source_verified',
          historicalIn: [], conflicted: false, diagnostics: [],
        } satisfies FindingSummary;
      });
    });
    snapshot.findings = fixtures;
    snapshot.assessments = snapshot.assessments.map(assessment => {
      const own = fixtures.filter(finding => finding.runId === assessment.id);
      const inventory = [...new Set(own.flatMap(finding => finding.repositories))]
        .map(repository => ({ name: repository, path: repository }));
      return {
        ...assessment, repository: 'Synthetic commerce application', repositories: inventory,
        scopes: assessment.scopes.map(scope => ({ ...scope, repositories: inventory })),
        findingKeys: own.map(finding => finding.key), historicalFindingKeys: [],
        counts: {
          ...assessment.counts, total: own.length, confirmed: own.length,
          needsEnvironment: 0, historical: 0, historicalConfirmed: 0, historicalNeedsEnvironment: 0,
          unconfirmed: 0, nonPromoted: 0, rejected: 0,
          severity: Object.fromEntries(['critical', 'high', 'medium', 'low', 'info', 'unknown']
            .map(severity => [severity, own.filter(finding => finding.severity === severity).length])) as Record<Severity, number>,
          confirmedChains: own.filter(finding => finding.kind === 'chain').length,
          sourceOnly: own.length, dynamicallyVerified: 0,
          addedOutcomes: own.filter(finding => ['new_root', 'new_chain', 'impact_expansion'].includes(finding.classification ?? '')).length,
          newRoots: own.filter(finding => finding.classification === 'new_root').length,
          newChains: own.filter(finding => finding.classification === 'new_chain').length,
          impactExpansions: own.filter(finding => finding.classification === 'impact_expansion').length,
          revalidations: own.filter(finding => finding.classification === 'baseline_revalidation').length,
          corrections: 0,
        },
      };
    });
    snapshot.relations = []; snapshot.conflicts = []; snapshot.failures = [];
    await route.fulfill({ response, json: snapshot });
  });
}

async function openOverview(page: Page, theme: 'light' | 'dark') {
  // Set one persisted value before reload; accumulating init scripts would make
  // the theme depend on their unspecified execution order.
  await page.goto('/?view=overview');
  await page.evaluate(value => localStorage.setItem('stake-theme', value), theme);
  await page.reload();
  await expect(page.getByRole('heading', { level: 1, name: 'Assessment overview', exact: true })).toBeVisible();
  if (theme === 'dark') await expect(page.locator('html')).toHaveClass('dark');
  else await expect(page.locator('html')).not.toHaveClass('dark');
  await expect(page.getByRole('region', { name: regionNames.repositories, exact: true })
    .getByRole('button', { name: /^Explore confirmed outcomes in / })).toHaveCount(repositories.length);
  await page.evaluate(() => document.fonts.ready);
}

async function geometry(locator: Locator) {
  await expect(locator).toBeVisible();
  return locator.evaluate(element => {
    const bounds = element.getBoundingClientRect();
    return { x: bounds.x + window.scrollX, y: bounds.y + window.scrollY,
      right: bounds.right + window.scrollX, bottom: bounds.bottom + window.scrollY,
      width: bounds.width, height: bounds.height };
  });
}

test('dense Overview keeps each desktop column flowing and every mobile repository reachable', async ({ page }) => {
  test.setTimeout(90_000);
  const errors: string[] = [];
  page.on('pageerror', error => errors.push(error.message));
  await installDenseOverview(page);
  await page.emulateMedia({ reducedMotion: 'reduce' });
  await page.setViewportSize({ width: 1440, height: 1000 });

  for (const theme of ['light', 'dark'] as const) {
    await openOverview(page, theme);
    const regions = Object.fromEntries(await Promise.all(Object.entries(regionNames).map(async ([key, name]) =>
      [key, await geometry(page.getByRole('region', { name, exact: true }))] as const))) as Record<keyof typeof regionNames, Awaited<ReturnType<typeof geometry>>>;
    const { repositories: repository, context, handoff, advantage } = regions;
    // The asymmetric fixture is essential: a shared grid row hides this bug
    // when both cards happen to have the same height.
    expect(repository.height - handoff.height).toBeGreaterThan(150);
    expect(Math.abs(repository.y - handoff.y)).toBeLessThanOrEqual(2);
    expect(handoff.x).toBeGreaterThan(repository.right);
    expect(context.y - repository.bottom).toBeGreaterThanOrEqual(0);
    expect(context.y - repository.bottom).toBeLessThanOrEqual(30);
    expect(advantage.y - handoff.bottom).toBeGreaterThanOrEqual(0);
    expect(advantage.y - handoff.bottom).toBeLessThanOrEqual(30);
    expect(advantage.y).toBeLessThan(repository.bottom - 100);
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);
    await page.screenshot({ path: `/private/tmp/atstake-overview-density-${theme}-desktop.png`, fullPage: true, animations: 'disabled' });
  }

  await page.setViewportSize({ width: 390, height: 844 });
  await openOverview(page, 'dark');
  // The mobile reading order follows the two column groups, without overlap
  // or inaccessible content squeezed outside the viewport.
  let previousBottom: number | undefined;
  for (const name of [regionNames.priority, regionNames.repositories, regionNames.context, regionNames.handoff, regionNames.advantage]) {
    const region = page.getByRole('region', { name, exact: true });
    await expect(region.getByRole('heading', { name, exact: true })).toBeVisible();
    const bounds = await geometry(region);
    expect(bounds.x).toBeGreaterThanOrEqual(0);
    expect(bounds.right).toBeLessThanOrEqual(391);
    if (previousBottom !== undefined) {
      expect(bounds.y - previousBottom).toBeGreaterThanOrEqual(0);
      expect(bounds.y - previousBottom).toBeLessThanOrEqual(30);
    }
    previousBottom = bounds.bottom;
  }
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);
  await page.screenshot({ path: '/private/tmp/atstake-overview-density-dark-mobile.png', fullPage: true, animations: 'disabled' });

  for (const repository of repositories) {
    const region = page.getByRole('region', { name: regionNames.repositories, exact: true });
    for (const severity of severities) {
      await expect(region.getByRole('button', { name: `Explore ${severity} outcomes in ${repository}`, exact: true })).toBeVisible();
    }
    const action = region.getByRole('button', { name: `Explore confirmed outcomes in ${repository}`, exact: true });
    await action.focus(); await expect(action).toBeFocused();
    await page.keyboard.press('Enter');
    await expect(page.getByRole('heading', { name: 'Findings, in context.', exact: true })).toBeVisible();
    const query = new URL(page.url()).searchParams;
    expect(query.get('repo')).toBe(repository);
    expect(query.get('status')).toBe('confirmed'); expect(query.get('origin')).toBe('assessed');
    await expect(page.getByText('4 matching findings', { exact: true })).toBeVisible();
    await expect(page.locator('.findings-table tbody tr')).toHaveCount(4);
    await page.goto('/?view=overview');
    await expect(page.getByRole('heading', { level: 1, name: 'Assessment overview', exact: true })).toBeVisible();
  }
  expect(errors).toEqual([]);
});

import { test, expect, type Page } from '@playwright/test';
import type { WorkspaceSummary } from '../../src/domain/types';

// These additions are synthetic UI examples; the paired fixture server still owns
// all artifacts and evidence callbacks. No supplied report is changed or captured.
async function syntheticAssessmentContext(page: Page) {
  await page.route('**/api/workspace', async route => {
    const response = await route.fetch();
    const workspace = await response.json() as WorkspaceSummary;
    const ordinary = workspace.assessments.find(a => a.id === 'audit-fixture')!;
    ordinary.limitations = ['The synthetic deployment inventory was not supplied.', 'Dynamic reproduction was not performed for this example.'];
    ordinary.accounting.investigation_accounting = {
      counts: { unresolved_paths: null, evidence_limited: 0, unscheduled_work: 9 },
      truncated: { unresolved_paths: null, evidence_limited: 0, unscheduled_work: 8 },
      unresolved_paths: [{ id: 'PATH-001', reason: 'The synthetic callback routing is unknown.', resolution: { outcome: 'externally_blocked', missing_fact: 'The deployed queue binding.', next_action: 'Request the deployment binding inventory.' }, evidence_ref: 'sast/verified-findings.json:C-001' }],
      evidence_limited: [], unscheduled_work: [{ question_id: 'Q-009', reason: 'The synthetic retry branch remains outside the recorded allocation.' }],
    };
    const advantage = workspace.assessments.find(a => a.id === 'advantage-fixture')!;
    advantage.baselineReconciliation = [{ baseline_id: 'F-001', status: 'baseline_revalidation', reason: 'The original synthetic baseline evidence is retained in its assessed scope.' }];
    await route.fulfill({ response, json: workspace });
  });
}

test('assessment tabs expose source scope, exact accounting, question details and original evidence', async ({ page }) => {
  const errors: string[] = [];
  page.on('pageerror', error => errors.push(error.message));
  await syntheticAssessmentContext(page);
  await page.goto('/?view=assessment');
  await expect(page.getByRole('heading', { level: 1 })).toContainText('Know the scope.');
  await expect(page.getByLabel('Assessment', { exact: true })).toHaveValue('audit-fixture');
  await expect(page.getByRole('tab', { name: 'Overview', exact: true })).toHaveAttribute('data-state', 'active');
  await expect(page.getByRole('heading', { name: 'Limits that matter', exact: true })).toHaveCount(0);
  await page.screenshot({ path: '/private/tmp/atstake-assessment-desktop.png', fullPage: true });

  await page.getByRole('tab', { name: 'Source scope', exact: true }).click();
  const repositories = page.getByRole('table').first();
  await expect(repositories.getByRole('columnheader', { name: 'Assessed revision' })).toBeVisible();
  await expect(repositories.getByText('a'.repeat(40), { exact: true })).toBeVisible();
  await expect(repositories.getByText('storefront', { exact: true })).toBeVisible();

  await page.getByRole('tab', { name: 'Open questions', exact: true }).click();
  await expect(page.locator('.asmt-question-metrics .asmt-number-card').nth(1)).toContainText('Unknown');
  await page.getByRole('button', { name: /Unresolved attack paths/ }).click();
  await expect(page.locator('.asmt-cohort-meta').first()).toContainText('Total: Unknown');
  await page.getByRole('button', { name: /PATH-001/ }).click();
  await expect(page.getByRole('definition').filter({ hasText: /^The deployed queue binding\.$/ })).toBeVisible();
  await expect(page.getByRole('definition').filter({ hasText: /^Request the deployment binding inventory\.$/ })).toBeVisible();
  await page.getByRole('button', { name: 'sast/verified-findings.json:C-001', exact: true }).click();
  await expect(page.getByRole('dialog')).toContainText('Synthetic canonical support.');
  await page.keyboard.press('Escape');
  await page.getByRole('button', { name: /Recorded investigation totals/ }).click();
  await expect(page.locator('.asmt-total-table>div').filter({ hasText: 'Evidence Limited' })).toHaveText('Evidence Limited0');
  await expect(page.locator('.asmt-total-table>div').filter({ hasText: 'Unresolved Paths' })).toHaveText('Unresolved PathsUnknown');

  await page.getByRole('tab', { name: 'Evidence', exact: true }).click();
  await expect(page.getByRole('button', { name: /Advanced provenance & accounting/ })).toHaveAttribute('aria-expanded', 'false');
  for (const label of ['Report JSON', 'Report Markdown', 'Final findings']) {
    await page.getByRole('button', { name: label, exact: true }).click();
    await expect(page.getByRole('dialog')).toBeVisible();
    await expect(page.getByRole('dialog')).not.toContainText('This reference is not registered');
    await expect(page.getByRole('dialog')).toContainText(label === 'Report Markdown' ? 'Synthetic assessment' : 'audit-fixture');
    await page.keyboard.press('Escape');
  }
  expect(errors).toEqual([]);
});

test('assessment switcher keeps Advantage lineage and counts local to the selected execution', async ({ page }) => {
  await syntheticAssessmentContext(page);
  await page.goto('/?view=assessment');
  await page.getByRole('tab', { name: 'Open questions', exact: true }).click();
  await page.getByLabel('Assessment', { exact: true }).selectOption('advantage-fixture');
  await expect(page).toHaveURL(/run=advantage-fixture/);
  await page.reload();
  await expect(page.getByLabel('Assessment', { exact: true })).toHaveValue('advantage-fixture');
  await expect(page.getByLabel('Assessment', { exact: true }).getByRole('option')).toHaveCount(2);
  await expect(page.getByRole('tab', { name: 'Overview', exact: true })).toHaveAttribute('data-state', 'active');
  await expect(page.locator('.asmt-summary-strip .asmt-number-card').first()).toContainText('Confirmed findings1');
  await expect(page.locator('.asmt-summary-strip')).toContainText('Added outcomes');
  await expect(page.locator('.asmt-lineage')).toContainText('audit-fixture');
  await expect(page.locator('.asmt-lineage')).toContainText('Available in this workspace');
  await page.getByRole('button', { name: /Baseline decisions/ }).click();
  await page.getByRole('button', { name: /F-001/ }).click();
  await expect(page.locator('.asmt-record-content>p')).toHaveText('The original synthetic baseline evidence is retained in its assessed scope.');
  await page.getByRole('tab', { name: 'Evidence', exact: true }).click();
  await page.getByRole('button', { name: 'Report JSON', exact: true }).click();
  await expect(page.getByRole('dialog')).toContainText('advantage-fixture');
});

test('assessment remains usable on narrow screens with dark theme and reduced motion', async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await page.emulateMedia({ reducedMotion: 'reduce' });
  await syntheticAssessmentContext(page);
  await page.goto('/?view=assessment');
  await page.getByRole('button', { name: 'Use dark theme' }).click();
  await expect(page.locator('html')).toHaveClass('dark');
  for (const tab of ['Overview', 'Source scope', 'Open questions', 'Evidence']) {
    await page.getByRole('tab', { name: tab, exact: true }).click();
    await expect(page.getByRole('tab', { name: tab, exact: true })).toHaveAttribute('data-state', 'active');
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);
  }
  await page.getByRole('tab', { name: 'Overview', exact: true }).click();
  await page.getByLabel('Assessment', { exact: true }).selectOption('advantage-fixture');
  await page.evaluate(() => window.scrollTo(0, 0));
  await page.screenshot({ path: '/private/tmp/atstake-assessment-narrow.png', fullPage: true });
  expect(await page.evaluate(() => window.matchMedia('(prefers-reduced-motion: reduce)').matches)).toBe(true);
});

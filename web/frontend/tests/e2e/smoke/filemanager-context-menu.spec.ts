import { test, expect, type APIRequestContext, type Page } from '@playwright/test';
import { loginViaAPI } from '../fixtures/auth';

// Placement of the file-manager context menu. The menu used to be an
// absolutely positioned child of `.fm-body` clamped to that box, so a menu
// with more items than the file list is tall was pushed above the container
// and cut off by its `overflow: hidden` (and by naive's `.n-tabs-pane-wrapper`
// one level further out). The viewport here is short on purpose: it is what
// makes the menu outgrow the list. The file-manager API is fully route-mocked
// (no daemon required).

test.use({ viewport: { width: 1280, height: 600 } });

const FILES_TAB = /files|файлы|servers\.files/i;

const TS = 1752800000;

// Enough rows for the list to scroll and for a row to sit at the bottom edge.
const FILE_COUNT = 40;

function fileEntry(path: string) {
  const basename = path.split('/').pop() ?? path;
  const dot = basename.lastIndexOf('.');

  return {
    path,
    timestamp: TS,
    type: 'file',
    visibility: 'public',
    size: 64,
    dirname: '',
    basename,
    extension: dot > 0 ? basename.slice(dot + 1) : undefined,
    filename: dot > 0 ? basename.slice(0, dot) : basename,
    mode: 420,
  };
}

const menu = (page: Page) => page.locator('.fm-context-menu');

// The popover fades the menu in from `scale(.85)`, and a transformed box
// measures short, so every size assertion waits the enter transition out.
async function openMenuOn(page: Page, row: ReturnType<typeof fileRow>) {
  await row.first().click({ button: 'right' });
  await expect(menu(page)).toBeVisible();
  await page.waitForFunction(() => {
    const el = document.querySelector('.fm-context-menu')?.closest('.n-popover');
    if (!el) return false;
    const style = getComputedStyle(el);

    return style.opacity === '1' && /^(none|matrix\(1, 0, 0, 1, 0, 0\))$/.test(style.transform);
  });
}
const fileRow = (page: Page, name: string) =>
  page.locator('.fm-row--file', { hasText: name });

async function openFileManager(page: Page, request: APIRequestContext) {
  const token = await loginViaAPI(request);
  await page.addInitScript((t) => localStorage.setItem('auth_token', t), token);

  await page.route('**/api/servers/1/**', (route) => route.fulfill({ json: {} }));
  await page.route('**/api/servers/1', (route) =>
    route.fulfill({
      json: {
        id: 1,
        uid: '11111111-1111-1111-1111-111111111111',
        uuid: '11111111-1111-1111-1111-111111111111',
        uuid_short: '11111111',
        enabled: true,
        installed: 1,
        blocked: false,
        name: 'E2E FM Server',
        game_id: 'cs',
        ds_id: 1,
        game_mod_id: 1,
        server_ip: '127.0.0.1',
        server_port: 27015,
        online: false,
        game: { code: 'cs', name: 'Counter-Strike' },
      },
    }),
  );
  await page.route('**/api/servers/1/abilities', (route) =>
    route.fulfill({
      json: { 'game-server-common': true, 'game-server-files': true },
    }),
  );
  await page.route('**/api/file-manager/1/**', (route) =>
    route.fulfill({ json: { result: { status: 'success', message: '' } } }),
  );
  await page.route('**/api/file-manager/1/initialize*', (route) =>
    route.fulfill({
      json: {
        result: { status: 'success', message: null },
        config: {
          acl: false,
          disks: { server: { driver: 'local' } },
          lang: 'en',
          leftDisk: 'server',
          leftPath: '',
          windowsConfig: 1,
        },
      },
    }),
  );
  await page.route('**/api/file-manager/1/content*', (route) =>
    route.fulfill({
      json: {
        result: { status: 'success', message: null },
        directories: [],
        files: Array.from({ length: FILE_COUNT }, (_, i) =>
          fileEntry(`file${String(i + 1).padStart(2, '0')}.txt`),
        ),
      },
    }),
  );

  await page.goto('/servers/1');
  await page
    .locator('.n-tabs-tab', { hasText: FILES_TAB })
    .click({ timeout: 20_000 });
  await expect(fileRow(page, 'file01.txt').first()).toBeVisible({
    timeout: 20_000,
  });
}

// The regression itself: the menu is taller than the list it is opened over.
async function expectMenuTallerThanList(page: Page) {
  const menuHeight = (await menu(page).boundingBox())?.height ?? 0;
  const bodyHeight = await page
    .locator('.fm-body')
    .evaluate((el) => el.getBoundingClientRect().height);

  expect(
    menuHeight,
    'the spec only proves anything while the menu outgrows the file list',
  ).toBeGreaterThan(bodyHeight);
}

// What the bug actually looked like: the menu keeps its box, so bounding-box
// and visibility checks pass while the part of it outside the file list is
// painted over by everything around. Hit-testing every item is the check that
// tells a drawn menu from a reachable one.
async function expectEveryItemReachable(page: Page) {
  await expect
    .poll(
      async () =>
        page.evaluate(() => {
          const menuEl = document.querySelector('.fm-context-menu');
          if (!menuEl) return ['<no menu in the DOM>'];

          return Array.from(menuEl.querySelectorAll('li'))
            .filter((li) => {
              const box = li.getBoundingClientRect();
              const hit = document.elementFromPoint(
                box.left + box.width / 2,
                box.top + box.height / 2,
              );

              return hit === null || !menuEl.contains(hit);
            })
            .map((li) => li.textContent?.trim() ?? '<empty>');
        }),
      { message: 'menu items covered by the page or cut off screen' },
    )
    .toEqual([]);
}

async function expectInsideViewport(page: Page) {
  const box = await menu(page).boundingBox();
  const viewport = page.viewportSize();

  expect(box).not.toBeNull();
  expect(viewport).not.toBeNull();
  expect(box!.y, 'menu top is cut off above the viewport').toBeGreaterThanOrEqual(0);
  expect(box!.x, 'menu left is cut off').toBeGreaterThanOrEqual(0);
  expect(box!.y + box!.height, 'menu bottom runs past the viewport').toBeLessThanOrEqual(
    viewport!.height,
  );
  expect(box!.x + box!.width, 'menu right runs past the viewport').toBeLessThanOrEqual(
    viewport!.width,
  );
}

test('a menu taller than the file list is not clipped by it', async ({
  page,
  request,
}) => {
  test.setTimeout(120_000);
  await openFileManager(page, request);

  await openMenuOn(page, fileRow(page, 'file01.txt'));
  await expectMenuTallerThanList(page);

  await expectEveryItemReachable(page);
  await expectInsideViewport(page);
});

test('a menu opened at the bottom edge opens upwards', async ({
  page,
  request,
}) => {
  test.setTimeout(120_000);
  await openFileManager(page, request);

  const rows = page.locator('.fm-content-body .fm-row--file');
  const listBottom = await page
    .locator('.fm-content-body')
    .evaluate((el) => el.getBoundingClientRect().bottom);

  // The last row whose middle is still inside the visible part of the list.
  const count = await rows.count();
  let target = rows.first();
  for (let i = count - 1; i >= 0; i--) {
    const box = await rows.nth(i).boundingBox();
    if (box && box.y + box.height <= listBottom) {
      target = rows.nth(i);
      break;
    }
  }

  const targetBox = await target.boundingBox();
  await openMenuOn(page, target);
  await expectMenuTallerThanList(page);
  await expectEveryItemReachable(page);
  await expectInsideViewport(page);

  const menuBox = await menu(page).boundingBox();
  expect(
    menuBox!.y,
    'a menu that does not fit below the cursor must open above it',
  ).toBeLessThan(targetBox!.y);
});

test('scrolling the file list closes the menu', async ({ page, request }) => {
  test.setTimeout(120_000);
  await openFileManager(page, request);

  await openMenuOn(page, fileRow(page, 'file01.txt'));

  await page.locator('.fm-content-body').evaluate((el) => {
    el.scrollTop = 120;
  });

  await expect(menu(page)).toHaveCount(0);
});

test('Escape closes the menu and keeps the selection', async ({
  page,
  request,
}) => {
  test.setTimeout(120_000);
  await openFileManager(page, request);

  const row = fileRow(page, 'file01.txt').first();
  await openMenuOn(page, row);
  await expect(row).toHaveClass(/fm-row--selected/);

  await page.keyboard.press('Escape');

  await expect(menu(page)).toHaveCount(0);
  await expect(row).toHaveClass(/fm-row--selected/);
});

test('the menu reopens on another row after it was closed', async ({
  page,
  request,
}) => {
  test.setTimeout(120_000);
  await openFileManager(page, request);

  await openMenuOn(page, fileRow(page, 'file01.txt'));

  await page.keyboard.press('Escape');
  await expect(menu(page)).toHaveCount(0);

  // Straight into a second menu: the popover keeps the leaving body around
  // for its transition, so a reopen can land on a reused element.
  await openMenuOn(page, fileRow(page, 'file03.txt'));
  await expect(fileRow(page, 'file03.txt').first()).toHaveClass(/fm-row--selected/);
  await expectEveryItemReachable(page);

  // And once more without closing it first.
  await openMenuOn(page, fileRow(page, 'file05.txt'));
  await expect(fileRow(page, 'file05.txt').first()).toHaveClass(/fm-row--selected/);
  await expectEveryItemReachable(page);
});

test('scrolling the page keeps the menu on its row', async ({ page, request }) => {
  test.setTimeout(120_000);
  await openFileManager(page, request);

  const row = fileRow(page, 'file01.txt').first();
  await openMenuOn(page, row);

  const before = {
    row: (await row.boundingBox())!.y,
    menu: (await menu(page).boundingBox())!.y,
    scroll: await page.evaluate(() => window.scrollY),
  };

  // The view settles at a scroll offset of its own, which may already be the
  // bottom of the page, so scroll whichever way there is room for.
  await page.evaluate(
    (d) => window.scrollBy(0, d),
    before.scroll > 0 ? -Math.min(30, before.scroll) : 30,
  );

  const after = {
    row: (await row.boundingBox())!.y,
    menu: (await menu(page).boundingBox())!.y,
    scroll: await page.evaluate(() => window.scrollY),
  };

  expect(after.scroll, 'the page has to actually scroll for this to mean anything')
    .not.toBe(before.scroll);
  // The menu is anchored in page coordinates, so it travels with its row and
  // a page scroll is no reason to take it away.
  await expect(menu(page)).toBeVisible();
  expect(after.menu - after.row).toBeCloseTo(before.menu - before.row, 0);
});

test('a menu opened at the right edge of the list stays on screen', async ({
  page,
  request,
}) => {
  test.setTimeout(120_000);
  await openFileManager(page, request);

  const row = fileRow(page, 'file01.txt').first();
  const box = (await row.boundingBox())!;
  await row.click({
    button: 'right',
    position: { x: box.width - 4, y: box.height / 2 },
  });
  await expect(menu(page)).toBeVisible();
  await expectEveryItemReachable(page);
  await expectInsideViewport(page);
});

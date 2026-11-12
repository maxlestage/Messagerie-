// Régénère toutes les icônes PNG des apps et du site à partir de branding/logo.svg.
//   node branding/render_icons.js        (depuis la racine du dépôt, Playwright requis)
// Le logo est centré sur fond blanc ; `fill` est la part du plus petit côté qu'il occupe.
const { chromium } = require('playwright');
const fs = require('fs');
const path = require('path');

const root = path.resolve(__dirname, '..');
const svg = fs.readFileSync(path.join(__dirname, 'logo.svg'), 'utf8');
const src = 'data:image/svg+xml;base64,' + Buffer.from(svg).toString('base64');

const ios = 'Brocolis/Assets.xcassets';
const imsg = 'BrocolisiMessage/Assets.xcassets/iMessage App Icon.stickersiconset';
const targets = [
  [`${ios}/AppIcon.appiconset/AppIcon-1024.png`, 1024, 1024, 0.86],
  [`${ios}/BrocolisLogo.imageset/BrocolisLogo-1024.png`, 1024, 1024, 0.86],
  ['BrocolisWatch/Assets.xcassets/AppIcon.appiconset/AppIcon-1024.png', 1024, 1024, 0.86],
  ['android/app/src/main/res/drawable/brocolis_logo.png', 1024, 1024, 0.86],
  // Icône adaptative : le lanceur peut masquer jusqu'au cercle de 72/108.
  ['android/app/src/main/res/drawable/brocolis_logo_foreground.png', 1024, 1024, 0.58],
  ['site/assets/photo.png', 640, 640, 0.86],
  ...[
    [1024, 768, '1024x768'], [54, 40, '27x20@2x'], [81, 60, '27x20@3x'],
    [58, 58, '29x29@2x'], [87, 87, '29x29@3x'], [64, 48, '32x24@2x'],
    [96, 72, '32x24@3x'], [120, 90, '60x45@2x'], [180, 135, '60x45@3x'],
    [58, 58, 'ipad-29x29@2x'], [134, 100, 'ipad-67x50@2x'], [148, 110, 'ipad-74x55@2x'],
  ].map(([w, h, n]) => [`${imsg}/icon-${n}.png`, w, h, 0.86]),
];

(async () => {
  const browser = await chromium.launch();
  for (const [rel, w, h, fill] of targets) {
    const page = await browser.newPage({ viewport: { width: w, height: h }, deviceScaleFactor: 1 });
    const side = Math.round(fill * Math.min(w, h));
    await page.setContent(`<html><body style="margin:0;background:#fff;width:${w}px;height:${h}px;
      display:flex;align-items:center;justify-content:center">
      <img src="${src}" style="width:${side}px;height:${side}px"></body></html>`);
    await page.waitForFunction(() => document.images[0].complete);
    await page.screenshot({ path: path.join(root, rel), omitBackground: false });
    await page.close();
    console.log(rel, `${w}x${h}`);
  }
  await browser.close();
})();

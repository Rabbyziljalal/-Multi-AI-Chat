// Generates the 4 PWA icon PNGs (192, 512 + maskable versions)
// using the exact chat-bubble gradient logo from the app.
const sharp = require('sharp');
const fs = require('fs');
const path = require('path');

const ICONS_DIR = path.join(__dirname, 'icons');
if (!fs.existsSync(ICONS_DIR)) fs.mkdirSync(ICONS_DIR);

// Shared gradient defs (background + logo) for a single flat SVG document.
const DEFS_SVG = `
  <defs>
    <linearGradient id="bgGrad" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" stop-color="#00d4ff"/>
      <stop offset="50%" stop-color="#7b2ff7"/>
      <stop offset="100%" stop-color="#ff2d92"/>
    </linearGradient>
    <linearGradient id="logoGrad1" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" stop-color="#00d4ff"/>
      <stop offset="50%" stop-color="#7b2ff7"/>
      <stop offset="100%" stop-color="#ff2d92"/>
    </linearGradient>
    <linearGradient id="logoGrad2" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" stop-color="#00d4ff" stop-opacity="0.9"/>
      <stop offset="100%" stop-color="#7b2ff7" stop-opacity="0.9"/>
    </linearGradient>
  </defs>
`;

// The exact chat-bubble logo path/geometry from the app's sidebar/header/welcome.
// viewBox "0 0 180 180".
const LOGO_SVG = `
  <circle cx="90" cy="90" r="82" stroke="url(#logoGrad1)" stroke-width="2" opacity="0.5" fill="none"/>
  <circle cx="90" cy="90" r="74" stroke="url(#logoGrad1)" stroke-width="1" opacity="0.3" fill="none" stroke-dasharray="5 5"/>
  <path d="M90 32 C58 32, 36 54, 36 82 C36 98, 46 112, 62 120 L62 142 L86 124 C87 124, 89 124, 90 124 C122 124, 144 102, 144 82 C144 54, 122 32, 90 32Z"
        fill="url(#logoGrad1)" opacity="0.18"/>
  <path d="M90 38 C63 38, 44 57, 44 82 C44 96, 52 108, 66 115 L66 132 L82 119 C84 119, 87 119, 90 119 C117 119, 136 100, 136 82 C136 57, 117 38, 90 38Z"
        fill="none" stroke="url(#logoGrad1)" stroke-width="3"/>
  <path d="M62 70 Q78 60, 94 70 T118 70" fill="none" stroke="url(#logoGrad2)" stroke-width="2.5" stroke-linecap="round"/>
  <path d="M68 82 Q82 73, 98 82 T122 82" fill="none" stroke="url(#logoGrad2)" stroke-width="2.5" stroke-linecap="round"/>
  <path d="M74 94 Q86 86, 100 94" fill="none" stroke="url(#logoGrad2)" stroke-width="2.5" stroke-linecap="round"/>
  <circle cx="52" cy="52" r="6.5" fill="#00d4ff"/>
  <circle cx="128" cy="52" r="6.5" fill="#7b2ff7"/>
  <circle cx="52" cy="112" r="6.5" fill="#ff2d92"/>
  <circle cx="128" cy="112" r="6.5" fill="#00d4ff"/>
  <line x1="58" y1="55" x2="76" y2="68" stroke="#00d4ff" stroke-width="1.5" opacity="0.55"/>
  <line x1="122" y1="55" x2="104" y2="68" stroke="#7b2ff7" stroke-width="1.5" opacity="0.55"/>
  <line x1="58" y1="109" x2="76" y2="96" stroke="#ff2d92" stroke-width="1.5" opacity="0.55"/>
  <line x1="122" y1="109" x2="104" y2="96" stroke="#00d4ff" stroke-width="1.5" opacity="0.55"/>
`;

// Builds a single flat square icon SVG: gradient background + logo.
// scaleFactor: how large the logo is relative to the square.
//   - 1.0 = logo fills the square (standard "any" icons)
//   - 0.6 = logo scaled down with ~20% safe-zone padding on all sides (maskable icons)
function buildIconSvg(scaleFactor) {
  const logoSize = 180 * scaleFactor;
  const offset = (180 - logoSize) / 2;
  const transform = `translate(${offset} ${offset}) scale(${scaleFactor})`;
  return `<svg xmlns="http://www.w3.org/2000/svg" width="180" height="180" viewBox="0 0 180 180">
  ${DEFS_SVG}
  <rect width="180" height="180" fill="url(#bgGrad)"/>
  <g transform="${transform}">
    ${LOGO_SVG}
  </g>
</svg>`;
}

async function renderIcon(fileName, size, scaleFactor) {
  const svg = buildIconSvg(scaleFactor);
  const outPath = path.join(ICONS_DIR, fileName);
  await sharp(Buffer.from(svg), { density: 300 })
    .png()
    .resize(size, size)
    .toFile(outPath);
  console.log('Generated', fileName, `(${size}x${size})`);
}

(async () => {
  await renderIcon('icon-192.png', 192, 1.0);
  await renderIcon('icon-512.png', 512, 1.0);
  await renderIcon('icon-maskable-192.png', 192, 0.6);
  await renderIcon('icon-maskable-512.png', 512, 0.6);
  console.log('All 4 icons generated in /icons');
})();
import math, random, sys
random.seed(7)
out = sys.argv[1]

# Bouquets (cx, cy, r), du fond vers l'avant.
florets = [
    (470, 225, 118),  # haut milieu (fond)
    (645, 250, 112),  # haut droite (fond)
    (300, 305, 120),  # gauche
    (740, 380, 104),  # droite
    (565, 335, 128),  # centre droite
    (300, 455, 96),   # bas gauche
    (645, 500, 100),  # bas droite
    (435, 400, 136),  # centre avant
]

def dome(cx, cy, r, out, bud):
    """Un petit dôme couvert de bourgeons, éclairé en haut à gauche."""
    out.append(f'<circle cx="{cx+r*.08:.1f}" cy="{cy+r*.14:.1f}" r="{r:.1f}" fill="#0c2a0a" opacity=".55" filter="url(#soft2)"/>')
    out.append(f'<circle cx="{cx:.1f}" cy="{cy:.1f}" r="{r:.1f}" fill="url(#mass)"/>')
    pts = []
    n = int((r / bud) ** 2 * 0.9)
    for _ in range(n):
        a = random.uniform(0, 2 * math.pi)
        d = r * math.sqrt(random.uniform(0, 1)) * 0.92
        pts.append((cy + d * math.sin(a), cx + d * math.cos(a), bud * random.uniform(.8, 1.25)))
    k = max(8, int(2 * math.pi * r / (bud * 1.5)))
    for j in range(k):
        a = 2 * math.pi * j / k + random.uniform(-.06, .06)
        pts.append((cy + r * .96 * math.sin(a), cx + r * .96 * math.cos(a), bud * random.uniform(.85, 1.1)))
    for y, x, br in sorted(pts):
        out.append(f'<circle cx="{x:.1f}" cy="{y:.1f}" r="{br:.1f}" fill="url(#bump)"/>')
    out.append(f'<circle cx="{cx:.1f}" cy="{cy:.1f}" r="{r*1.03:.1f}" fill="url(#shade)"/>')

def floret(cx, cy, r, i):
    g = ['<g>']
    g.append(f'<circle cx="{cx+8}" cy="{cy+14}" r="{r}" fill="#0c2a0a" opacity=".6" filter="url(#soft)"/>')
    g.append(f'<circle cx="{cx}" cy="{cy}" r="{r*.97:.1f}" fill="#1a4714"/>')
    # Petits dômes : couronne extérieure puis centre, de l'arrière vers l'avant.
    domes = []
    m = 7
    for j in range(m):
        a = 2 * math.pi * j / m + random.uniform(-.2, .2) + i
        d = r * random.uniform(.55, .62)
        domes.append((cx + d * math.cos(a), cy + d * math.sin(a), r * random.uniform(.4, .47)))
    domes.append((cx - r * .06, cy - r * .06, r * .5))
    domes.sort(key=lambda t: t[1] + (1000 if t[2] >= r * .5 else 0))
    for x, y, dr in domes:
        dome(x, y, dr, g, bud=max(4.2, r * .05))
    g.append(f'<circle cx="{cx}" cy="{cy}" r="{r*1.02:.1f}" fill="url(#shadeBig)"/>')
    g.append('</g>')
    return '\n'.join(g)

backing = '\n'.join(f'<circle cx="{cx}" cy="{cy}" r="{r*0.9:.0f}"/>' for cx, cy, r in florets)
crown = f'<g fill="#173f12">{backing}</g>' + '\n'.join(floret(*f, i) for i, f in enumerate(florets))

svg = f'''<svg xmlns="http://www.w3.org/2000/svg" viewBox="92 96 856 856" width="856" height="856">
<defs>
  <linearGradient id="ring" x1="0" y1="0" x2="1" y2="1">
    <stop offset="0" stop-color="#b9ec7a"/>
    <stop offset=".45" stop-color="#6cc24a"/>
    <stop offset="1" stop-color="#2b8a3e"/>
  </linearGradient>
  <linearGradient id="stem" gradientUnits="userSpaceOnUse" x1="300" y1="686" x2="430" y2="758">
    <stop offset="0" stop-color="#6fb52d"/>
    <stop offset=".35" stop-color="#b7e36c"/>
    <stop offset=".6" stop-color="#8fcf45"/>
    <stop offset="1" stop-color="#4f9a22"/>
  </linearGradient>
  <linearGradient id="branch" gradientUnits="userSpaceOnUse" x1="300" y1="0" x2="720" y2="0">
    <stop offset="0" stop-color="#7cc23a"/>
    <stop offset=".4" stop-color="#a6dc5c"/>
    <stop offset="1" stop-color="#5a9f2a"/>
  </linearGradient>
  <linearGradient id="stemShade" gradientUnits="userSpaceOnUse" x1="0" y1="470" x2="0" y2="720">
    <stop offset="0" stop-color="#1f5a14" stop-opacity=".75"/>
    <stop offset=".45" stop-color="#1f5a14" stop-opacity=".2"/>
    <stop offset="1" stop-color="#1f5a14" stop-opacity="0"/>
  </linearGradient>
  <radialGradient id="mass" cx=".4" cy=".35" r=".7">
    <stop offset="0" stop-color="#4f9a2e"/>
    <stop offset="1" stop-color="#1e5518"/>
  </radialGradient>
  <radialGradient id="bump" cx=".38" cy=".32" r=".7">
    <stop offset="0" stop-color="#9fd86a"/>
    <stop offset=".3" stop-color="#55a332"/>
    <stop offset=".75" stop-color="#2a6b1f"/>
    <stop offset="1" stop-color="#143d10"/>
  </radialGradient>
  <radialGradient id="shade" cx=".32" cy=".28" r=".8">
    <stop offset="0" stop-color="#e4fbb0" stop-opacity=".38"/>
    <stop offset=".4" stop-color="#d8f5a0" stop-opacity="0"/>
    <stop offset=".7" stop-color="#0d300c" stop-opacity=".2"/>
    <stop offset="1" stop-color="#0a260a" stop-opacity=".7"/>
  </radialGradient>
  <linearGradient id="bubble" x1="0" y1="0" x2="0" y2="1">
    <stop offset="0" stop-color="#ffffff"/>
    <stop offset="1" stop-color="#eef3ec"/>
  </linearGradient>
  <filter id="soft" x="-20%" y="-20%" width="140%" height="140%"><feGaussianBlur stdDeviation="10"/></filter>
  <filter id="soft2" x="-30%" y="-30%" width="160%" height="160%"><feGaussianBlur stdDeviation="5"/></filter>
  <radialGradient id="shadeBig" cx=".3" cy=".25" r=".85">
    <stop offset="0" stop-color="#e4fbb0" stop-opacity=".22"/>
    <stop offset=".45" stop-color="#e4fbb0" stop-opacity="0"/>
    <stop offset=".8" stop-color="#0a260a" stop-opacity=".12"/>
    <stop offset="1" stop-color="#0a260a" stop-opacity=".45"/>
  </radialGradient>
  <filter id="drop" x="-20%" y="-20%" width="140%" height="140%">
    <feGaussianBlur in="SourceAlpha" stdDeviation="9"/>
    <feOffset dx="4" dy="8"/>
    <feComponentTransfer><feFuncA type="linear" slope=".3"/></feComponentTransfer>
    <feMerge><feMergeNode/><feMergeNode in="SourceGraphic"/></feMerge>
  </filter>
  <filter id="grain">
    <feTurbulence type="fractalNoise" baseFrequency=".9" numOctaves="2" seed="3"/>
    <feColorMatrix values="0 0 0 0 0  0 0 0 0 0  0 0 0 0 0  0 0 0 -1.4 1.1"/>
    <feComposite in2="SourceGraphic" operator="in"/>
  </filter>
</defs>

<!-- Anneau -->
<circle cx="520" cy="530" r="396" fill="none" stroke="url(#ring)" stroke-width="46"/>

<g filter="url(#drop)">
  <!-- Tige : tronc qui s'évase en ramifications sous la couronne -->
  <path d="M235 835 C285 750 335 675 372 612 C345 585 318 548 298 505 L345 482 C368 520 392 548 418 566 C422 525 422 490 416 452 L472 448 C477 492 480 526 484 556 C540 545 598 518 640 488 L668 524 C622 568 560 600 505 622 C455 705 400 790 345 878 C320 905 255 895 235 835 Z" fill="url(#stem)"/>
  <path d="M235 835 C285 750 335 675 372 612 C345 585 318 548 298 505 L345 482 C368 520 392 548 418 566 C422 525 422 490 416 452 L472 448 C477 492 480 526 484 556 C540 545 598 518 640 488 L668 524 C622 568 560 600 505 622 C455 705 400 790 345 878 C320 905 255 895 235 835 Z" fill="url(#stemShade)"/>
  <path d="M288 836 C330 760 372 690 420 618" stroke="#e1f8a8" stroke-width="12" stroke-linecap="round" fill="none" opacity=".6"/>
  <path d="M440 600 C445 560 446 530 444 500" stroke="#e1f8a8" stroke-width="8" stroke-linecap="round" fill="none" opacity=".45"/>
  <path d="M338 858 C380 785 420 715 466 640" stroke="#3f8a1c" stroke-width="7" stroke-linecap="round" fill="none" opacity=".3"/>
  <ellipse cx="288" cy="862" rx="58" ry="24" transform="rotate(-150 288 862)" fill="#cdf090" stroke="#7dbb3d" stroke-width="5"/>
  <ellipse cx="288" cy="862" rx="34" ry="12" transform="rotate(-150 288 862)" fill="#b4e070" opacity=".7"/>

  <!-- Couronne -->
  <g>{crown}</g>
</g>

<!-- Bulle de discussion -->
<g filter="url(#drop)">
  <path d="M760 612 C858 612 915 668 915 742 C915 818 858 872 760 872
           C735 872 712 868 692 862 L612 906 L640 836
           C615 812 603 780 603 742 C603 668 662 612 760 612 Z"
        fill="url(#bubble)" stroke="#2c6e2e" stroke-width="22" stroke-linejoin="round"/>
  <circle cx="695" cy="742" r="25" fill="#2c6e2e"/>
  <circle cx="760" cy="742" r="25" fill="#2c6e2e"/>
  <circle cx="825" cy="742" r="25" fill="#2c6e2e"/>
</g>
</svg>'''
open(out, 'w').write(svg)

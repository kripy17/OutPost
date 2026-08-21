# Branding Assets — Favicon & Terminal Banner

## Favicon

`favicon.svg` (repo root of this doc bundle) uses the exact color tokens from `docs/07-UI-DESIGN-SYSTEM.md` — dark slate background, amber root node, teal + amber branch nodes. It's a small version of the same branching visual language used for the process tree elsewhere in the app, so the icon and the product's actual "hero" visual are the same idea at different scales.

**Where it goes:** `frontend/public/favicon.svg`, referenced in `frontend/index.html`:

```html
<link rel="icon" type="image/svg+xml" href="/favicon.svg" />
```

SVG favicons render natively in all current browsers and stay crisp at any size — no need to also generate a `.ico` unless you specifically want fallback support for very old browsers, which isn't a concern for a portfolio/demo project.

## Terminal ASCII Banner

Two versions — a full banner for primary commands, a compact one for frequently-run read commands where a big banner would just be noise.

**Primary banner** (`outpost`, `outpost watch`, `outpost run`, `outpost --help`):

```
  ___   _   _  _____   ____   _____  _____
 / _ \ | | | ||_   _| |  _ \ / _ \ \| |/ /
| | | || | | |  | |   | |_) | | | |  / _ \
| |_| || |_| |  | |   |  __/  | |_| |_|/ /
 \___/  \___/   |_|   |_|     \___/ |___/
```

**Compact banner** (used for `outpost list`, `outpost show`, `outpost search`, `outpost export` — commands you'll run repeatedly and don't need re-branded every time):

```
  ___  _   _  _____  ____   ____  _____
 / _ \| | | ||_   _||  _ \ / ___| |_   _|
| | | || | | |  | | | |_) |\___ \  | |
| |_| || |_| |  | | |  __/  ___) | | |
 \___/ \___/   |_| |_|    |____/  |_|
```

Both generated with `pyfiglet` (`slant` and `small` fonts respectively) rather than hand-drawn, so the alignment is guaranteed correct — if you ever want to regenerate or try other fonts: `pip install pyfiglet --break-system-packages`, then `pyfiglet.figlet_format("OUTPOST", font="...")`.

### Wiring into the CLI (`cli/outpost/rendering/terminal_views.py`)

```python
from rich.console import Console

console = Console()

PRIMARY_BANNER = r"""[bold]
  ___   _   _  _____   ____   _____  _____
 / _ \ | | | ||_   _| |  _ \ / _ \ \| |/ /
| | | || | | |  | |   | |_) | | | |  / _ \
| |_| || |_| |  | |   |  __/  | |_| |_|/ /
 \___/  \___/   |_|   |_|     \___/ |___/
[/bold][dim]behavioral security monitor[/dim]
"""

COMPACT_BANNER = r"""[bold]
  ___  _   _  _____  ____   ____  _____
 / _ \| | | ||_   _||  _ \ / ___| |_   _|
| | | || | | |  | | | |_) |\___ \  | |
| |_| || |_| |  | | |  __/  ___) | | |
 \___/ \___/   |_| |_|    |____/  |_|
[/bold]"""

def show_banner(primary: bool = True):
    # Suppress entirely when output isn't a real terminal (piped/redirected) —
    # a banner in a log file or a script's captured output is just noise.
    if not console.is_terminal:
        return
    console.print(PRIMARY_BANNER if primary else COMPACT_BANNER, style="cyan")
```

Color the banner with the accent amber from `docs/07-UI-DESIGN-SYSTEM.md` (`#D9A441`) rather than plain cyan if you want to match the webapp's identity exactly — Rich supports hex colors directly: `style="#D9A441"`.

### Rule of thumb for which banner (or none) to show

- `outpost` (no args) and `outpost --help` → primary banner
- `outpost watch` and `outpost run` (the two commands that start a session) → primary banner, it's a deliberate "starting something" moment
- `outpost list`, `show`, `search`, `export`, `compare`, `notes` → compact banner, or skip entirely if you want these to feel fast rather than ceremonial
- Any non-TTY output (piped to a file, run in CI, etc.) → no banner at all, ever — check `console.is_terminal` before printing it

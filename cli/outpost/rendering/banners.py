"""Terminal banners for `outpost`.

Per docs/12-BRANDING-ASSETS.md the banners are pyfiglet-generated (`slant`
and `small` fonts). We generate them at runtime so alignment is guaranteed,
and fall back to the verified literals if pyfiglet isn't installed.

Banner is suppressed entirely for non-TTY output (piped/CI) — a banner in a
log file is just noise.
"""

from rich.console import Console

console = Console()

_PRIMARY_FALLBACK = r"""  ___   _   _  _____   ____   _____  _____
 / _ \ | | | ||_   _| |  _ \ / _ \ \| |/ /
| | | || | | |  | |   | |_) | | | |  / _ \
| |_| || |_| |  | |   |  __/  | |_| |_|/ /
 \___/  \___/   |_|   |_|     \___/ |___/"""

_COMPACT_FALLBACK = r"""  ___  _   _  _____  ____   ____  _____
 / _ \| | | ||_   _||  _ \ / ___| |_   _|
| | | || | | |  | | | |_) |\___ \  | |
| |_| || |_| |  | | |  __/  ___) | | |
 \___/ \___/   |_| |_|    |____/  |_|"""


def _figlet(text: str, font: str) -> str | None:
    try:
        import pyfiglet

        return pyfiglet.figlet_format(text, font=font).rstrip("\n")
    except Exception:
        return None


def _banner(text: str, font: str, fallback: str) -> str:
    return _figlet(text, font) or fallback


def show_banner(primary: bool = True) -> None:
    """Print the full (primary) or compact banner — only on a real TTY."""
    if not console.is_terminal:
        return
    text = _banner("OUTPOST", "slant", _PRIMARY_FALLBACK) if primary else _banner("OUTPOST", "small", _COMPACT_FALLBACK)
    console.print(f"[bold #D9A441]{text}[/bold #D9A441]")
    if primary:
        console.print("[dim]behavioral security monitor[/dim]")

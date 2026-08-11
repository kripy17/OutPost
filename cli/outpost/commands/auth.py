"""`outpost auth` — credential helpers for the optional auth gate.

The backend never stores plaintext passwords: each role's password is verified
against a salted PBKDF2-SHA256 hash. This command generates such a hash so an
operator can either

  - export OUTPOST_ADMIN_PASSWORD_HASH="$(outpost auth hash)"   (env bootstrap)
  - POST it to /auth/password once the server is running         (DB rotation)

The hash format matches backend core/auth.py exactly
(`pbkdf2_sha256$<iters>$<salt_hex>$<dk_hex>`), implemented here with stdlib
only — the CLI is deliberately dependency-light.

`outpost auth rotate-agent-token` rotates the shared agent credential end to
end: generate (or accept) a new token, store it on the backend (DB-stored
wins over the env bootstrap value), and re-embed it into this host's agent
config.
"""

import getpass
import hashlib
import os
import secrets
import sys

import requests
import typer
from rich.console import Console

app = typer.Typer(help="Authentication helpers (passwords + agent token)", add_completion=False)
console = Console()

_ALGO = "pbkdf2_sha256"
_ITERATIONS = 210_000  # must match backend core/auth.py


def hash_password(password: str, iterations: int = _ITERATIONS) -> str:
    """Salt + PBKDF2-SHA256 a password; returns the self-describing hash string."""
    salt = os.urandom(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, iterations)
    return f"{_ALGO}${iterations}${salt.hex()}${dk.hex()}"


@app.command()
def hash(
    password: str = typer.Argument(
        None,
        help="Password to hash. Omitted → prompted (never echoed).",
    ),
):
    """Generate a PBKDF2 password hash for OUTPOST_*_PASSWORD_HASH or the API."""
    if password is None:
        password = getpass.getpass("Password: ")
    if not password:
        console.print("[red]Password cannot be empty.[/red]")
        raise typer.Exit(2)
    console.print(hash_password(password))
    console.print(
        "\n[dim]Set OUTPOST_ADMIN_PASSWORD_HASH (or ANALYST) to this value, or POST it to "
        "/auth/password with an admin token to store it in the DB.[/dim]"
    )
    return None

@app.command()
def rotate_agent_token(
    token: str = typer.Option(
        "",
        help="New agent token. Omitted → generated as a random 48-hex string.",
    ),
    backend_url: str = typer.Option(
        os.getenv("OUTPOST_API_URL", "http://localhost:8000"),
        envvar="OUTPOST_API_URL",
        help="Backend base URL",
    ),
    admin_password: str = typer.Option(
        None,
        "--admin-password",
        prompt=True,
        hide_input=True,
        envvar="OUTPOST_ADMIN_PASSWORD",
        help="Admin password — rotates the agent token (env OUTPOST_ADMIN_PASSWORD avoids the prompt)",
    ),
):
    """Rotate the shared agent credential end to end.

    1. New token: the given `--token` or a generated 48-hex string.
    2. Backend: log in as admin and POST /auth/agent-token — the DB-stored
       value wins over the env bootstrap token immediately, so the old value
       is inert without a redeploy.
    3. Local agent config: re-run the install generation with the new token
       (systemd unit / scheduled-task .bat files) so this host's service
       authenticates on its next restart.
    Other monitored hosts: re-run `outpost agent install --agent-token <new>`
    on each, or update their OUTPOST_AGENT_TOKEN env.
    """
    new = token.strip() or secrets.token_hex(24)
    if len(new) < 16:
        console.print("[red]Token too short — use at least 16 characters.[/red]")
        raise typer.Exit(2)

    base = backend_url.rstrip("/")
    login = requests.post(f"{base}/auth/login", json={"password": admin_password or ""}, timeout=15)
    if login.status_code != 200:
        console.print(f"[red]Admin login failed (HTTP {login.status_code}): {login.text[:200]}[/red]")
        raise typer.Exit(2)
    admin_token = login.json()["token"]

    rotated = requests.post(
        f"{base}/auth/agent-token",
        json={"token": new},
        headers={"Authorization": f"Bearer {admin_token}"},
        timeout=15,
    )
    if rotated.status_code != 200:
        console.print(f"[red]Rotation failed (HTTP {rotated.status_code}): {rotated.text[:200]}[/red]")
        raise typer.Exit(2)
    console.print("[green]Agent token rotated on the backend (DB-stored — old env value is now inert).[/green]")

    # Re-embed into this host's agent service config (systemd / scheduled
    # task .bat). Same generation `outpost agent install` uses.
    from ..commands.agent import _write_service_config

    try:
        unit, enable = _write_service_config(base, new)
    except Exception as exc:  # noqa: BLE001 — report and still surface the token
        console.print(f"[yellow]Local agent config re-embed failed: {exc}[/yellow]")
        console.print(f"[bold]New OUTPOST_AGENT_TOKEN:[/bold] {new}")
        raise typer.Exit(1)
    console.print(f"[green]Re-embedded local agent config:[/green] {unit}")
    console.print(f"\n[bold]New OUTPOST_AGENT_TOKEN:[/bold] {new}")
    enable_lines = (enable or "").splitlines()
    if enable_lines:
        console.print(f"[dim]Enable on this host:[/dim] {enable_lines[0]}")
    console.print(
        "[dim]Other monitored hosts: re-run `outpost agent install --agent-token <new>` on each.[/dim]"
    )


if __name__ == "__main__":
    app()

"""`outpost auth` — credential helpers for the optional auth gate.

The backend never stores plaintext passwords: each role's password is verified
against a salted PBKDF2-SHA256 hash. This command generates such a hash so an
operator can either

  - export OUTPOST_ADMIN_PASSWORD_HASH="$(outpost auth hash)"   (env bootstrap)
  - POST it to /auth/password once the server is running         (DB rotation)

The hash format matches backend core/auth.py exactly
(`pbkdf2_sha256$<iters>$<salt_hex>$<dk_hex>`), implemented here with stdlib
only — the CLI is deliberately dependency-light.
"""

import getpass
import hashlib
import os
import sys

import typer
from rich.console import Console

app = typer.Typer(help="Authentication helpers (password hashing)", add_completion=False)
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


if __name__ == "__main__":
    app()

"""`python -m outpost` entry — parity with the installed binary and with
`python -m outpost.main` (which the generated systemd summary unit uses)."""

from .main import app

if __name__ == "__main__":
    app()

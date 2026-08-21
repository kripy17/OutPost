"""`outpost auth hash` — the generated hash must match the backend's format
(pbkdf2_sha256$<iters>$<salt>$<dk>) so it can be dropped straight into
OUTPOST_ADMIN_PASSWORD_HASH or POSTed to /auth/password."""

from outpost.commands.auth import hash_password


def test_auth_hash_format_matches_backend():
    h = hash_password("s3cret")
    assert h.startswith("pbkdf2_sha256$")
    parts = h.split("$")
    assert len(parts) == 4  # algo, iterations, salt, dk
    assert parts[1].isdigit() and int(parts[1]) >= 100_000


def test_auth_hash_is_salted_and_unique():
    a = hash_password("same-pass")
    b = hash_password("same-pass")
    assert a != b  # random salt → distinct hashes for the same password


def test_auth_hash_deterministic_verify():
    # The CLI's own verifier round-trips (used by tests; the backend has the
    # authoritative verify_password — format parity is what matters here).
    import hashlib
    import hmac as hmac_mod

    h = hash_password("x")
    algo, iters, salt_hex, dk_hex = h.split("$", 3)
    dk = hashlib.pbkdf2_hmac("sha256", b"x", bytes.fromhex(salt_hex), int(iters))
    assert hmac_mod.compare_digest(dk.hex(), dk_hex)

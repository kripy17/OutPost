"""Tests for live host forensic hunting probes."""

import pytest

from app.services import forensic_probes


def test_list_forensic_probes():
    probes = forensic_probes.list_forensic_probes()
    assert len(probes) >= 5
    probe_ids = [p["id"] for p in probes]
    assert "crontab_persistence" in probe_ids
    assert "ssh_authorized_keys" in probe_ids
    assert "deleted_binaries" in probe_ids
    assert "suspicious_sockets" in probe_ids
    assert "suid_lotl_binaries" in probe_ids
    assert "systemd_services" in probe_ids
    assert "shell_profiles" in probe_ids
    assert "ld_preload_hijack" in probe_ids
    assert "kernel_rootkits" in probe_ids
    assert "pam_backdoors" in probe_ids


def test_run_suid_probe():
    res = forensic_probes.run_forensic_probe("suid_lotl_binaries")
    assert res["probe_id"] == "suid_lotl_binaries"
    assert "findings" in res
    assert isinstance(res["findings"], list)


def test_run_sockets_probe():
    res = forensic_probes.run_forensic_probe("suspicious_sockets")
    assert res["probe_id"] == "suspicious_sockets"
    assert "findings" in res
    assert isinstance(res["findings"], list)


def test_run_systemd_probe():
    res = forensic_probes.run_forensic_probe("systemd_services")
    assert res["probe_id"] == "systemd_services"
    assert res["tactic"] == "Persistence"
    assert res["technique"] == "T1543.002"
    assert "findings" in res
    assert isinstance(res["findings"], list)


def test_run_shell_profiles_probe():
    res = forensic_probes.run_forensic_probe("shell_profiles")
    assert res["probe_id"] == "shell_profiles"
    assert res["tactic"] == "Persistence"
    assert res["technique"] == "T1546.004"
    assert "findings" in res
    assert isinstance(res["findings"], list)


def test_run_ld_preload_probe():
    res = forensic_probes.run_forensic_probe("ld_preload_hijack")
    assert res["probe_id"] == "ld_preload_hijack"
    assert res["tactic"] == "Defense Evasion"
    assert res["technique"] == "T1574.006"
    assert "findings" in res
    assert isinstance(res["findings"], list)


def test_run_kernel_modules_probe():
    res = forensic_probes.run_forensic_probe("kernel_rootkits")
    assert res["probe_id"] == "kernel_rootkits"
    assert res["tactic"] == "Persistence"
    assert res["technique"] == "T1547.006"
    assert "findings" in res
    assert isinstance(res["findings"], list)


def test_run_rwx_memory_probe():
    res = forensic_probes.run_forensic_probe("rwx_memory_injection")
    assert res["probe_id"] == "rwx_memory_injection"
    assert res["tactic"] == "Defense Evasion"
    assert res["technique"] == "T1055"
    assert "findings" in res
    assert isinstance(res["findings"], list)


def test_run_dns_hosts_probe():
    res = forensic_probes.run_forensic_probe("dns_hosts_hijack")
    assert res["probe_id"] == "dns_hosts_hijack"
    assert res["tactic"] == "Impact"
    assert res["technique"] == "T1565.001"
    assert "findings" in res
    assert isinstance(res["findings"], list)


def test_run_pam_backdoors_probe():
    res = forensic_probes.run_forensic_probe("pam_backdoors")
    assert res["probe_id"] == "pam_backdoors"
    assert res["tactic"] == "Credential Access"
    assert res["technique"] == "T1556"
    assert "findings" in res
    assert isinstance(res["findings"], list)


def test_collect_host_triage_pack_manifest():
    pack = forensic_probes.collect_host_triage_pack(include_yara=False)
    assert "triage_id" in pack
    assert "manifest" in pack
    manifest = pack["manifest"]
    assert manifest["collector"] == "OutPost Sovereign DFIR Engine 1.0"
    assert manifest["standard"] == "NIST SP 800-86 Cryptographic Evidence Integrity"
    assert "manifest_sha256" in manifest
    assert len(manifest["manifest_sha256"]) == 64
    assert "section_hashes" in manifest
    assert "metrics" in manifest["section_hashes"]
    assert "probe_results" in manifest["section_hashes"]
    assert "chain_of_custody" in manifest
    assert manifest["chain_of_custody"]["acquired_by"] == "OutPost Sovereign Workstation"


def test_unknown_probe_raises():
    with pytest.raises(ValueError):
        forensic_probes.run_forensic_probe("non_existent_probe_xyz")


def test_pam_probe_ignores_stock_common_auth(tmp_path, monkeypatch):
    """Stock Ubuntu common-auth ('auth required pam_permit.so') must NOT false-positive as backdoor."""
    from pathlib import Path
    pam_mock = tmp_path / "pam.d"
    pam_mock.mkdir()

    # Stock Ubuntu common-auth
    (pam_mock / "common-auth").write_text(
        "auth [success=1 default=ignore] pam_unix.so nullok\n"
        "auth requisite pam_deny.so\n"
        "auth required pam_permit.so\n"
    )
    # Malicious backdoor in sudo
    (pam_mock / "sudo").write_text(
        "auth sufficient pam_permit.so\n"
    )

    monkeypatch.setattr(forensic_probes, "Path", lambda p: pam_mock if p == "/etc/pam.d" else Path(p))
    results = forensic_probes.hunt_pam_backdoors()
    assert len(results) == 1
    assert results[0]["service"] == "sudo"
    assert "pam_permit.so" in results[0]["module"]
    assert results[0]["severity"] == "critical"


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


def test_unknown_probe_raises():
    with pytest.raises(ValueError):
        forensic_probes.run_forensic_probe("non_existent_probe_xyz")

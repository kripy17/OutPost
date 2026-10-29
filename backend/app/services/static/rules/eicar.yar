rule EICAR_Standard_Antivirus_Test_File {
    meta:
        description = "Standard EICAR anti-malware test file pattern"
        author = "OutPost Security Team"
        severity = "high"
        verdict_impact = "authoritative"
        reference = "https://www.eicar.org"
        mitre_technique = "T1059"
    strings:
        $eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    condition:
        $eicar
}

rule PowerShell_Download_Cradle {
    meta:
        description = "PowerShell in-memory download cradle execution"
        author = "OutPost Security Team"
        severity = "high"
        verdict_impact = "authoritative"
        mitre_technique = "T1059.001"
    strings:
        $webclient = "Net.WebClient" nocase
        $down_str = "DownloadString" nocase
        $down_file = "DownloadFile" nocase
        $down_data = "DownloadData" nocase
        $iex1 = "IEX" nocase
        $iex2 = "Invoke-Expression" nocase
    condition:
        $webclient and ($down_str or $down_file or $down_data) and ($iex1 or $iex2)
}

rule PowerShell_Hidden_Bypass {
    meta:
        description = "PowerShell hidden window execution policy bypass"
        author = "OutPost Security Team"
        severity = "medium"
        verdict_impact = "authoritative"
        mitre_technique = "T1562.001"
    strings:
        $ps = "powershell" nocase
        $bypass = "-ExecutionPolicy Bypass" nocase
        $hidden = "-WindowStyle Hidden" nocase
    condition:
        $ps and $bypass and $hidden
}

rule Bash_Dev_TCP_Reverse_Shell {
    meta:
        description = "Bash /dev/tcp interactive reverse shell invocation"
        author = "OutPost Security Team"
        severity = "high"
        verdict_impact = "authoritative"
        mitre_technique = "T1059.004"
    strings:
        $dev_tcp = "/dev/tcp/"
        $bash_i = "bash -i"
        $redirect = ">& /dev/tcp/"
        $sh_i = "sh -i"
    condition:
        $dev_tcp and ($bash_i or $redirect or $sh_i)
}

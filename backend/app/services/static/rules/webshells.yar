rule Generic_PHP_Webshell {
    meta:
        description = "Generic PHP webshell command execution pattern"
        author = "OutPost Security Team"
        severity = "high"
        verdict_impact = "authoritative"
        mitre_technique = "T1505.003"
    strings:
        $php_open = "<?php" nocase
        $eval = "eval(" nocase
        $assert = "assert(" nocase
        $sys = "system(" nocase
        $passthru = "passthru(" nocase
        $shell_exec = "shell_exec(" nocase
        $post = "$_POST"
        $get = "$_GET"
        $req = "$_REQUEST"
    condition:
        $php_open and ($eval or $assert or $sys or $passthru or $shell_exec) and ($post or $get or $req)
}

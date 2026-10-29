rule UPX_Compressed_Binary {
    meta:
        description = "UPX executable packer compression signature"
        author = "OutPost Security Team"
        severity = "medium"
        verdict_impact = "informational"
        reference = "https://upx.github.io"
    strings:
        $upx_magic = "UPX!"
        $upx0 = "UPX0"
        $upx1 = "UPX1"
    condition:
        (uint16(0) == 0x5A4D and ($upx_magic or ($upx0 and $upx1))) or
        (uint32(0) == 0x464C457F and $upx_magic)
}

rule ASPack_Compressed_PE {
    meta:
        description = "ASPack executable packer section signature"
        author = "OutPost Security Team"
        severity = "medium"
        verdict_impact = "informational"
    strings:
        $aspack1 = ".aspack"
        $aspack2 = ".adata"
    condition:
        uint16(0) == 0x5A4D and ($aspack1 or $aspack2)
}

rule MPRESS_Compressed_PE {
    meta:
        description = "MPRESS executable packer section signature"
        author = "OutPost Security Team"
        severity = "medium"
        verdict_impact = "informational"
    strings:
        $mpress1 = ".MPRESS1"
        $mpress2 = ".MPRESS2"
    condition:
        uint16(0) == 0x5A4D and ($mpress1 or $mpress2)
}

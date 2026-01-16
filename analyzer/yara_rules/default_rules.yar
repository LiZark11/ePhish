rule Suspicious_Packed_File {
    meta:
        description = "Detects heavily packed files typical of malware"
    strings:
        $entropy_high = { 00 00 00 00 ?? ?? ?? ?? 00 00 00 00 } // High entropy patterns
    condition:
        filesize > 1024 and
        uint32(0) == 0x5A4D and // PE header
        entropy(0, filesize) > 7.0
}

rule Executable_Extension_Mismatch {
    meta:
        description = "Detects executable files with non-executable extensions"
    condition:
        uint32(0) == 0x5A4D and // PE header
        extension matches /\.doc$|\.pdf$|\.jpg$|\.png$/i
}

rule Suspicious_API_Calls {
    meta:
        description = "Detects suspicious Windows API calls"
    strings:
        $create_process = "CreateProcess"
        $write_memory = "WriteProcessMemory"
        $virtual_alloc = "VirtualAlloc"
    condition:
        $create_process or $write_memory or $virtual_alloc
}

rule Known_Malware_Signature {
    meta:
        description = "Known malware signature patterns"
    strings:
        $trojan_sig = { 4D 5A ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 02 }
    condition:
        $trojan_sig
}
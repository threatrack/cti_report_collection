import "pe"
rule uninstall_exe {
meta:
    description = "Yara rule for uninstall SFX archive"
    author = "Cybaze - Yoroi ZLab"
    last_updated = "2019-05-22"
    tlp = "white"
    category = "informational"
strings:
    $a1 = { E8 68 BA 01 00 51 }
    $a2 = { 58 E9 8B C6 4F 6F 7A }
    $a3 = { D9 4E D5 FA D4 34 }

condition:
    pe.number_of_resources == 24 and all of them
}
rule excel_dropper {
meta:
    description = "Yara rule for excel dropper"
    author = "Cybaze - Yoroi ZLab"
    last_updated = "2019-05-22"
    tlp = "white"
    category = "informational"
strings:
    $a1 = { 98 C3 AB F0 E7 F3 BD F4 }
    $a2 = { 41 6E D5 7E F0 10 AB A7 }
    $a3 = "gxbgarjktzyu"
    $a4 = "Bob Brown"

condition:
    all of them
}
import "pe"
rule winserv_exe {
meta:
    description = "Yara rule for winserv backdoor"
    author = "Cybaze - Yoroi ZLab"
    last_updated = "2019-05-22"
    tlp = "white"
    category = "informational"
strings:
    $a1 = "MPRESS1"
    $a2 = { 90 C4 73 05 E6 92 }
    $a3 = { E9 64 4B 56 3F EC }
    $a4 = { 10 EF D0 E1 36 E1 14 3C }

condition:
    all of them and pe.version_info["CompanyName"] contains "tox"
}
import "pe"
rule veter_random {
meta:
    description = "Yara rule for veter_trojan"
    author = "Cybaze - Yoroi ZLab"
    last_updated = "2019-05-22"
    tlp = "white"
    category = "informational"
strings:
    $a = { 5E C2 04 00 F6 44 24 04 01 56 }
    
    $b1 = { 01 8B 02 8B 48 04 03}
    $b2 = { 4A 3B C2 7E 08 8B C2 }
    
    $c1 = { E8 83 CA 04 89 55 E8 }
    $c2 = { 1F DF 70 07 22 84 82 }

condition:
    $a and (($b1 and $b2 and pe.version_info["CompanyName"] contains "Miranda") or ($c1 and $c2 and pe.version_info["InternalName"] contains "DrldwgRom"))
}
import "pe"
rule pasmmm_exe {
meta:
    description = "Yara rule for pasmmm SFX archive"
    author = "Cybaze - Yoroi ZLab"
    last_updated = "2019-05-22"
    tlp = "white"
    category = "informational"
strings:
    $a1 = { 1C Cf 43 39 C8 32 B4 B0 }
    $a2 = { 60 6C B8 7C 5F FA }
    $a3 = "LookupPrivilege"
    $a4 = "LoadBitmap"

condition:
    pe.number_of_sections == 6 and all of them
}

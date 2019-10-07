import "pe"
rule Office_Commu_22_02_2019{

    meta:
    description = "Yara Rule for Office_Commu"
    author = "Cybaze Zlab_Yoroi"
    last_updated = "2019_02_22"
    tlp = "white"
    category = "informational"

    strings:
            $a = {61 E0 4B A1 1D C6 2F A7}
            $b = {8F D2 A9 E3 70 5A B4 D9 92 1D BA}
            $c = "Kill"
            $d = {DB 71 F5 4C B0 29 27 20 B8}
            $e = "get_IsAlive"

    condition:
            pe.number_of_sections == 3 and all of them
}
import "pe"
rule Powerkatz_22_02_2019{

    meta:
    description = "Yara Rule for Powerkatz"
    author = "Cybaze Zlab_Yoroi"
    last_updated = "2019_02_22"
    tlp = "white"
    category = "informational"

    strings:
            $a1 = {C7 E8 3F}
            $b1 = {7C 43 3D}
            $a2 = {A4 58 24 8A 3A 36 8D 4B 89 15 15 33 CE 1D 1D F2}
            $b2 = {A9 B5 2D 2A 00 47 AC 44 97 7A F5 D0 04 09 75 13}

    condition:
            pe.number_of_sections == 3 and pe.machine == pe.MACHINE_I386 and (($a1 or $b1) and ($a2 or $b2))
}
import "pe"
rule eba_sample_22_02_2019{

    meta:
    description = "Yara Rule for 1eba_sample"
    author = "Cybaze Zlab_Yoroi"
    last_updated = "2019_02_22"
    tlp = "white"
    category = "informational"

    strings:
            $a = {4A 02 73 29 00 00 0A 7D}
            $b = {F8 01 7A 00 1B 00 54 28}
            $c = "portScan"
            $d = {C9 45 99 B9 AA AD C7 46}
            $e = "parseHost"

    condition:
            pe.number_of_sections == 3 and all of them
}
import "pe"
rule LazyCat_22_02_2019{

    meta:
    description = "Yara Rule for LazyCat"
    author = "Cybaze Zlab_Yoroi"
    last_updated = "2019_02_22"
    tlp = "white"
    category = "informational"

    strings:
        $a = "LazyCat"
            $b = {48 74 74 70 53 65 72 76 65 72 4C 6F}
            $c = {0A 58 73 9E 00 00 0A 2A 0F 00 28 B0}
            $d = {80 A1 4E CD 13 56 80 9F}

    condition:
            pe.number_of_sections == 3 and pe.machine == pe.MACHINE_I386 and (($b and $c and $d) or ($a))
}

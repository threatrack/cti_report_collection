rule  RTF_Malicous_Object

    {
    meta:
        author  = "Anomali"
        tlp           = "GREEN"
        version       = "1.0"
        date          = "2018-11-13"
        hash          = "9d0c4ec62abe79e754eaa2fd7696f98441bc783781d8656065cddfae3dbf503e"
        Bulletin        = "https://ui.threatstream.com/tip/262672/"
        description   = "Rule to detect Malicious RTF based on object dimension "

    strings:

    $S1= "objw871\\objh811\\objscalex8\\objscaley8"
    $RTF= "{\\rt"

    condition:

    $RTF at 0 and $S1
    }
rule RTF_weaponizer_objh300

    {
    meta:
        author        = "Anomali"
        tlp           = "GREEN"
        version       = "1.0"
        date          = "2018-11-13"
        hash          = "9d0c4ec62abe79e754eaa2fd7696f98441bc783781d8656065cddfae3dbf503e"
        Bulletin        = "https://ui.threatstream.com/tip/262672/"
        description   = "Rule to detect Malicious RTF based on object dimension "

    strings:

    $S1= "objw2180\\objh300"
    $RTF= "{\\rt"

    condition:

    $RTF at 0 and $S1
    }

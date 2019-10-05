rule pistacchietto_campaign_0219 {   
    meta:
        description = "Yara rule for Pistacchietto campaign"
        author = "Yoroi ZLab - Cybaze"
        last_updated = "2019-03-01"
        tlp = "white"
        category = "informational"

    strings:
        $nc = "nc.exe" wide ascii
        $nc64 = "nc64.exe" wide ascii
        $dns1 = "config02.addns.org" wide ascii
        $dns2 = "config01.homepc.it" wide ascii
        $dns3 = "verifiche.ddns.net" wide ascii
        $dns4 = "paner.altervista.org" wide ascii
        $dns5 = "certificates.ddns.net" wide ascii
        $id = "pistacchietto" wide ascii
        $path = "/svc/wup.php?pc=" wide ascii
    condition:
        (1 of ($nc*)) and (1 of ($dns*)) or $id or $path
}

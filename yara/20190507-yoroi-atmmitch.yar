import "pe"
rule ATMitch {
meta:
      description = "Yara Rule for ATMitch Dropper/Payload"
      author = "ZLAB Yoroi - Cybaze"
      last_updated = "2019-05-03"
      tlp = "white"
      category = "informational"

   strings:
        $str1 = {4A 75 E6 8B C7 8B 4D FC}
         $str2 = {EC 53 8D 4D DC 88}
        $str3 = "MSXFS.dll"
        $str4 = "DISPENSE"
        $str5 = "PinPad"
        $str6 = "cash"
        $str7 = {40 59 41 50 41 58 49 40 5A}
        $str8 = "WFMFreeBuffer"

condition:
    pe.number_of_sections == 4 and pe.number_of_resources == 3 and $str1 and $str2 or $str3 and $str4 and $str5 and $str6 and $str7 and $str8
}

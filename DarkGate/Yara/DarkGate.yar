rule Windows_Trojan_DarkGate {
    meta:
        description = "Detects Trojan DarkGate"
        author = "Kadircan Kaya"
        approver = "Yasin Kalli"
        date = "2024-08-12"
        version = "1.0"
        reference_sample = "1fce9ee9254dd0641387cc3b6ea5f6a60f4753132c20ca03ce4eed2aa1042876"
        copyright = "InfoSEC"

    strings:
        $str0 = "DarkGate has recovered from a Critical error"
        $str1 = "Executing DarkGate inside the new desktop..."
        $str2 = "Restart Darkgate "

    condition:
        2 of them
}

rule Windows_Trojan_DarkGate {
    meta:
        description = "Detects Trojan DarkGate"
        author = "Kadircan Kaya"
        approver = "Yasin Kalli"
        date = "2024-08-12"
        version = "1.0"
        reference_sample = "1fce9ee9254dd0641387cc3b6ea5f6a60f4753132c20ca03ce4eed2aa1042876"
        copyright = "InfoSEC"

    strings:
        $binary0 = { 8B 04 24 0F B6 44 18 FF 33 F8 43 4E }
        $binary1 = { 8B D7 32 54 1D FF F6 D2 88 54 18 FF 43 4E }
    condition:
        all of them
}

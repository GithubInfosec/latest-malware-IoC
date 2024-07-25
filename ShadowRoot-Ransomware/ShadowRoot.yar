rule Ransomware_ShadowRoot 
{
    meta:
        description = "Detects ShadowRoot ransomware targeting Turkish businesses"
        author = "Kadircan Kaya"
        approver = "Yasin Kalli"
        version = "1.0"
        date = "2024-07-18"
        reference = "https://www.forcepoint.com/blog/x-labs/shadowroot-ransomware-targeting-turkish-businesses"
        copyright = "InfoSEC"

    strings:
        $url1 = "hxxps://raw[.]githubusercontent[.]com/kurumsaltahsilat/detayfatura/main/PDF.FaturaDetay_202407.exe" nocase wide
        $hash1 = "CD8FBF0DCDD429C06C80B124CAF574334504E99A"
        $hash2 = "1C9629AEB0E6DBE48F9965D87C64A7B8750BBF93"
        $email1 = "Kurumsal[.]tasilat[@]internet[.]ru" nocase wide
        $email2 = "ran_master_som[@]proton[.]me" nocase wide
        $email3 = "lasmuruk[@]mailfence[.]com" nocase wide

        $file1 = "C:\\TheDream\\RootDesign.exe" nocase wide
        $file2 = "C:\\TheDream\\Uninstall.exe" nocase wide
        $file3 = "C:\\TheDream\\Uninstall.ini" nocase wide
        $cmd1 = "C:\\Windows\\System32\\cmd.exe /c PowerShell.exe -windowstyle hidden powershell -c C:\\TheDream\\RootDesign.exe" nocase wide

        $mutex1 = "Local\\ZonesCacheCounterMutex"
        $mutex2 = "Local\\ZonesLockedCacheCounterMutex"
        $mutex3 = "_SHuassist.mtx"

        $cryptoClass = "AESCryptoServiceProvider" nocase wide

    condition:
        uint16(0) == 0x5A4D and
        (any of ($url*) or
        any of ($hash*) or
        any of ($email*) or
        any of ($file*) or
        any of ($cmd*) or
        any of ($mutex*) or
        $cryptoClass)
}

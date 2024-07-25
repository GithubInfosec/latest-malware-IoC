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
        sha1_1 = "6f9c3f5d9a1cba63b56d25112efcb3a89e1df7ad"
        sha1_2 = "bd5b0bc9f3a9150f3a972d495b1d1ac34e1bfed3"

    strings:
        $download_url = "hxxps://raw[.]githubusercontent[.]com/kurumsaltahsilat/detayfatura/main/PDF.FaturaDetay_202407.exe" nocase
        $email_1 = "ram_master_som[@]proton[.]me" nocase wide
        $email_2 = "lasmuruk[@]mailfence[.]com" nocase wide
        $mutex1 = "Local\\ZonesCacheCounterMutex" nocase wide
        $mutex2 = "Local\\ZonesLockedCacheCounterMutex" nocase wide
        $mutex3 = "_SHuassist.mtx" nocase wide
        $powershell_cmd = "C:\\Windows\\System32\\cmd.exe /c PowerShell.exe -windowstyle hidden powershell -c C:\\TheDream\\RootDesign.exe" nocase wide
        $log_string = "ApproveExit.dot" nocase wide
        $ransom_note = "Dosyalarınızın Kurtarılması için Talimatlar" nocase wide
        $smtp_c2 = "smtp[.]mail[.]ru" nocase

    condition:
        uint16(0) == 0x5A4D and
        (
            sha1(0, filesize) == "6f9c3f5d9a1cba63b56d25112efcb3a89e1df7ad" or
            sha1(0, filesize) == "bd5b0bc9f3a9150f3a972d495b1d1ac34e1bfed3" or
            $download_url or
            $email_1 or
            $email_2 or
            any of ($mutex1, $mutex2, $mutex3) or
            $powershell_cmd or
            $log_string or
            $ransom_note or
            $smtp_c2
        )
}

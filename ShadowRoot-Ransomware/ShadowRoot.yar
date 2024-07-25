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
        sha256_1 = "CD8FBF0DCDD429C06C80B124CAF574334504E99A"
        sha256_2 = "1C9629AEB0E6DBE48F9965D87C64A7B8750BBF93"

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
            sha256(0, filesize) == "CD8FBF0DCDD429C06C80B124CAF574334504E99A" or
            sha256(0, filesize) == "1C9629AEB0E6DBE48F9965D87C64A7B8750BBF93" or
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

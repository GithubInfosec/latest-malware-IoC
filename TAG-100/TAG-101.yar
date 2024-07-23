rule APT_TAG_100_Detection {
    meta:
        description = "Detects activity related to TAG-100 APT group"
        author = "Kadircan Kaya"
        approver = "Yasin Kalli"
        date = "2024-07-22"
        reference = "https://www.recordedfuture.com/research/tag-100-uses-open-source-tools-in-suspected-global-espionage-campaign"
        copyright = "InfoSEC"

    strings:
        $pantegana = "Pantegana"
        $sparkrat = "SparkRAT"
        $leslieloader = "LESLIELOADER"
        $cobalt_strike_beacon = "Jquery malleable C2 profile"
        $cross_c2 = "CrossC2"
        $c2_domain1 = "www.megtech.xyz"
        $c2_domain2 = "spweitaoj.kgoedeihk.raceceysd.rodsmoe.com"
        $ip1 = "216.238.68.36"
        $ip2 = "209.141.50.215"
        $ip3 = "172.67.70.10"
        $mutex1 = "Global\\{0D3A7DAA-F0E4-4334-BE7C-24B9BC3C8E0F}"
        $mutex2 = "Global\\{DF983FCE-F2FA-4192-B665-0A2B792594BA}"
        $registry_key1 = "HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\SparkRAT"
        $registry_key2 = "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\LESLIELOADER"

    condition:
        any of ($pantegana, $sparkrat, $leslieloader, $cobalt_strike_beacon, $cross_c2) or
        any of ($c2_domain1, $c2_domain2, $ip1, $ip2, $ip3) or
        any of ($mutex1, $mutex2, $registry_key1, $registry_key2)
}

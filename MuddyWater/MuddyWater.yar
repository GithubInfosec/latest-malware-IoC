rule MuddyWater_BugSleep_Backdoor {
    meta:
        description = "Detects MuddyWater BugSleep backdoor"
        author = "Kadircan Kaya"
        approver = "Yasin Kalli"
        date = "2024-07-20"
        reference = "research.checkpoint.com"
        copyright = "InfoSEC"

    strings:
        $str1 = "PackageManager" ascii
        $str2 = "DocumentUpdater" ascii
        $str3 = "sample comment" ascii
        $path1 = "C:\\users\\public\\a.txt" ascii

        $ip1 = "146.19.143.14"
        $ip2 = "91.235.234.202"

        $domain1 = "kinneretacil.egnyte.com"
        $domain2 = "salary.egnyte.com"

        $url1 = "https://shorturl.at/NCxJk"
        $url2 = "https://shorturl.at/bYqUx"

        $hash1 = { 73 c6 77 dd 3b 26 4e 7e b8 0e 26 e7 8a c9 df 1d ba 30 91 5b 5c e3 b1 bc 1c 83 db 52 b9 c6 b3 0e }
        $hash2 = { 96 0d 4c 9e 79 e7 51 be 6c ad 47 0e 4f 8e 1d 3a 2b 11 f7 6f 47 59 7d f8 61 9a e4 1c 96 ba 58 09 }

    condition:
        any of ($str1, $str2, $str3, $path1, $ip1, $ip2, $domain1, $domain2, $url1, $url2, $hash1, $hash2)
}

rule MuddyWater_BugSleep_Hashes {
    meta:
        description = "Detects known hashes of MuddyWater BugSleep backdoor"
        author = "Kadircan Kaya"
        approver = "Yasin Kalli"
        date = "2024-07-20"
        reference = "research.checkpoint.com"
        copyright = "InfoSEC"

    strings:
        $hash1 = { 73 c6 77 dd 3b 26 4e 7e b8 0e 26 e7 8a c9 df 1d ba 30 91 5b 5c e3 b1 bc 1c 83 db 52 b9 c6 b3 0e }
        $hash2 = { 96 0d 4c 9e 79 e7 51 be 6c ad 47 0e 4f 8e 1d 3a 2b 11 f7 6f 47 59 7d f8 61 9a e4 1c 96 ba 58 09 }
        $hash3 = { b8 70 37 44 74 45 55 ad 84 1f 92 29 95 ce f5 db ca 11 da 22 56 51 95 d0 55 29 f5 f9 09 5f bf ca }
        $hash4 = { 94 27 8f a0 19 00 fd bf b5 8d 2e 37 38 95 c0 45 c6 9c 01 91 5e dc 53 49 cd 6f 3e 5b 71 30 c4 72 }
        $hash5 = { 5d f7 24 c2 20 ae d7 b4 87 8a 2a 55 75 02 a5 ce fe e7 36 40 6e 25 ca 48 ca 11 a7 06 08 f3 a1 c0 }

    condition:
        any of them
}

rule MuddyWater_BugSleep_Network_Indicators {
    meta:
        description = "Detects network indicators of MuddyWater BugSleep backdoor"
        author = "Kadircan Kaya"
        approver = "Yasin Kalli"
        date = "2024-07-20"
        reference = "research.checkpoint.com"
        copyright = "InfoSEC"

    strings:
        $ip1 = "146.19.143.14"
        $ip2 = "91.235.234.202"
        $ip3 = "85.239.61.97"
        $ip4 = "95.164.32.69"
        $ip5 = "5.252.23.52"
        $ip6 = "194.4.50.133"
        $ip7 = "193.109.120.59"
        $ip8 = "89.221.225.81"
        $ip9 = "45.150.108.198"
        $ip10 = "200.200.200.248"
        $ip11 = "169.150.227.230"
        $ip12 = "169.150.227.205"
        $ip13 = "185.248.85.20"
        $ip14 = "141.98.252.143"
        $ip15 = "31.171.154.54"
        $ip16 = "146.70.172.227"
        $ip17 = "198.54.131.36"

        $domain1 = "kinneretacil.egnyte.com"
        $domain2 = "salary.egnyte.com"
        $domain3 = "gcare.egnyte.com"
        $domain4 = "rimonnet.egnyte.com"
        $domain5 = "alltrans.egnyte.com"
        $domain6 = "megolan.egnyte.com"
        $domain7 = "bgu.egnyte.com"
        $domain8 = "fbcsoft.egnyte.com"
        $domain9 = "cnsmportal.egnyte.com"
        $domain10 = "alkan.egnyte.com"
        $domain11 = "getter.egnyte.com"
        $domain12 = "ksa1.egnyte.com"
        $domain13 = "filecloud.egnyte.com"
        $domain14 = "nour.egnyte.com"
        $domain15 = "airpazfly.egnyte.com"
        $domain16 = "cairoairport.egnyte.com"
        $domain17 = "silbermintz1.egnyte.com"
        $domain18 = "smartcloudcompany.com"
        $domain19 = "onlinemailerservices.com"
        $domain20 = "smtpcloudapp.com"
        $domain21 = "softwarehosts.com"
        $domain22 = "airpaz.egnyte.com"
        $domain23 = "airpazflys.egnyte.com"
        $domain24 = "fileuploadcloud.egnyte.com"
        $domain25 = "downloadfile.egnyte.com"

    condition:
        any of ($ip*, $domain*)
}

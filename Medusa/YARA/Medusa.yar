rule Medusa_Malware {
    meta:
        description = "Detects Medusa banking trojan variants"
        author = "Kadircan Kaya"
        approver = "Yasin Kalli"
        date = "2024-07-20"
        version = "1.0"
        reference = "https://www.cleafy.com/cleafy-labs/medusa-reborn-a-new-compact-variant-discovered"
        copyright = "InfoSEC"

    strings:
        $medusa_strings = "Medusa" ascii nocase
        $url1 = "a2a2a2a.life" ascii nocase
        $url2 = "pemmbebebebebebe.info" ascii nocase
        $url3 = "unkunknunkkkkk.info" ascii nocase
        $url4 = "cincincintopcin.info" ascii nocase
        $url5 = "tony1303sock.top" ascii nocase
        $perm1 = "ACCESSIBILITY_SERVICE" ascii nocase
        $perm2 = "BROADCAST_SMS" ascii nocase
        $perm3 = "INTERNET" ascii nocase
        $perm4 = "FOREGROUND_SERVICE" ascii nocase
        $perm5 = "QUERY_ALL_PACKAGES" ascii nocase
        $perm6 = "DELETE_PACKAGES" ascii nocase
        $cmd1 = "destroyo" ascii nocase
        $cmd2 = "permdrawover" ascii nocase
        $cmd3 = "setoverlay" ascii nocase
        $cmd4 = "take_scr" ascii nocase
        $cmd5 = "update_sec" ascii nocase
        $str1 = "android.permission.RECEIVE_SMS" ascii nocase
        $str2 = "android.permission.SEND_SMS" ascii nocase
        $str3 = "android.permission.READ_CONTACTS" ascii nocase
        $str4 = "android.permission.WRITE_CONTACTS" ascii nocase
        $str5 = "android.permission.CALL_PHONE" ascii nocase
        $str6 = "android.permission.READ_PHONE_STATE" ascii nocase
        $str7 = "android.permission.READ_SMS" ascii nocase
        $str8 = "android.permission.WRITE_EXTERNAL_STORAGE" ascii nocase
        $str9 = "android.permission.READ_EXTERNAL_STORAGE" ascii nocase
        $hash1 = "d41d8cd98f00b204e9800998ecf8427e" ascii
        $hash2 = "e2fc714c4727ee9395f324cd2e7f331f" ascii
        $hash3 = "f6d6b2ff0d8f2bdc2e3f931bfc6ef5ff" ascii

    condition:
        any of ($medusa_strings, $url*, $perm*, $cmd*, $str*, $hash*)
}

rule Medusa_4K_Sports {
    meta:
        description = "Detects Medusa variant associated with '4K Sports'"
        author = "Kadircan Kaya"
        approver = "Yasin Kalli"
        date = "2024-07-20"
        version = "1.0"
        reference = "https://www.cleafy.com/cleafy-labs/medusa-reborn-a-new-compact-variant-discovered"
        copyright = "InfoSEC"

    strings:
        $app_name = "4K Sports" ascii nocase
        $url = "a4a4a4a.life" ascii nocase
        $hash1 = "1db5ce9cbb3932ce2e11e5b3cd900ee2" ascii
        $hash2 = "97abc0aa3819e161ca1f7f3e78025e15" ascii
        $hash3 = "8468c1cda925021ed911fd9c17915eec" ascii
        $file_name = "4K_Sports" ascii nocase

    condition:
        any of ($app_name, $url, $hash*, $file_name)
}

rule Medusa_Purolator {
    meta:
        description = "Detects Medusa variant associated with 'Purolator'"
        author = "Kadircan Kaya"
        approver = "Yasin Kalli"
        date = "2024-07-20"
        version = "1.0"
        reference = "https://www.cleafy.com/cleafy-labs/medusa-reborn-a-new-compact-variant-discovered"
        copyright = "InfoSEC"

    strings:
        $app_name = "Purolator" ascii nocase
        $url1 = "a4a4a4a.life" ascii nocase
        $url2 = "unkunknunkkkkk.info" ascii nocase
        $url3 = "cincincintopcin.info" ascii nocase
        $hash1 = "cb1280f6e63e4908d52b5bee6f65ec63" ascii
        $hash2 = "a5aeb6ccc48fea88cf6c6bcc69940f8a" ascii
        $hash3 = "bd7b9dd5ca8c414ff2c4744df41e7031" ascii
        $file_name = "Purolator" ascii nocase

    condition:
        any of ($app_name, $url*, $hash*, $file_name)
}

rule Medusa_Inat_TV_Video_Oynaticisi {
    meta:
        description = "Detects Medusa variant associated with 'İnat TV Video Oynaticisi'"
        author = "Kadircan Kaya"
        approver = "Yasin Kalli"
        date = "2024-07-20"
        version = "1.0"
        reference = "https://www.cleafy.com/cleafy-labs/medusa-reborn-a-new-compact-variant-discovered"
        copyright = "InfoSEC"

    strings:
        $app_name = "İnat TV Video Oynaticisi" ascii nocase
        $url = "tony1303sock.top" ascii nocase
        $hash1 = "4c12987ac5d56a35258b3b7cdc87f038" ascii
        $hash2 = "3fbe1323bdef176a6011a534e15a80f0" ascii
        $hash3 = "0e7c37e28871f439539b3d87242def55" ascii
        $file_name = "İnat_TV_Video_Oynaticisi" ascii nocase

    condition:
        any of ($app_name, $url, $hash*, $file_name)
}

rule Medusa_Chrome_Update {
    meta:
        description = "Detects Medusa variant associated with 'Chrome Güncelleme'"
        author = "Kadircan Kaya"
        approver = "Yasin Kalli"
        date = "2024-07-20"
        version = "1.0"
        reference = "https://www.cleafy.com/cleafy-labs/medusa-reborn-a-new-compact-variant-discovered"
        copyright = "InfoSEC"

    strings:
        $app_name = "Chrome Güncelleme" ascii nocase
        $url = "baahhhs21.info" ascii nocase
        $hash1 = "185f8c23fd680cae560aad220e137886" ascii
        $hash2 = "3b7df8e68eca9a4bcc559d79a2c5a4c7" ascii
        $file_name = "Chrome_Guncelleme" ascii nocase

    condition:
        any of ($app_name, $url, $hash*, $file_name)
}

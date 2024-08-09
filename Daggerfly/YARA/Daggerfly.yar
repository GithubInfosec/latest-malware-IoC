rule Trojan_Suzafk_Dropper
{
    meta:
        description = "Detects the Trojan.Suzafk dropper"
        author = "Kadircan Kaya"
        approver = "Yasin Kalli"
        date = "2024-07-26"
        version = "1.0"
        reference = "https://symantec-enterprise-blogs.security.com/threat-intelligence/daggerfly-espionage-updated-toolset"
        copyright = "InfoSEC"
        hash1 = "5687b32cdd5c4d1b3e928ee0792f6ec43817883721f9b86ec8066c5ec2791595"

    strings:
        $a = "ConnONEDRIVE" nocase
        $b = "ConnTCP" nocase
        $c = "4aa6708f-f3c8-4511-8118-5a7208be6a44" nocase
        $d = "103.96.131.150" nocase
        $e = "C:\\Programdata\\Office\\" nocase
    
    condition:
        uint32(0) == 0x4D5A and
        filesize < 100KB and
        ($a and $b and $c and $d and $e)
}

rule Trojan_Suzafk_DLL
{
    meta:
        description = "Detects the Trojan.Suzafk DLL"
        author = "Kadircan Kaya"
        approver = "Yasin Kalli"
        date = "2024-07-26"
        version = "1.0"
        reference = "https://symantec-enterprise-blogs.security.com/threat-intelligence/daggerfly-espionage-updated-toolset"
        copyright = "InfoSEC"
        hash1 = "49079ea789e75736f8f8fad804da4a99db52cbaca21e1d2b6d6e1ea4db56faad"
    
    strings:
        $dll_entry = "DllEntryPoint"
        $dll_string1 = "Engine.dll"
        $dll_string2 = "MeituUD.exe"
    
    condition:
        uint32(0) == 0x5A4D and
        filesize < 200KB and
        ($dll_entry and $dll_string1 and $dll_string2)
}

rule Macma_Backdoor
{
    meta:
        description = "Detects the Macma macOS backdoor"
        author = "Kadircan Kaya"
        approver = "Yasin Kalli"
        date = "2024-07-26"
        version = "1.0"
        reference = "https://symantec-enterprise-blogs.security.com/threat-intelligence/daggerfly-espionage-updated-toolset"
        copyright = "InfoSEC"
        hash1 = "003764fd74bf13cff9bf1ddd870cbf593b23e2b584ba4465114023870ea6fbef"
        hash2 = "dad13b0a9f5fde7bcdda3e5afa10e7d83af0ff39288b9f11a725850b1e6f6313"
    
    strings:
        $macma_str1 = "Device fingerprinting" nocase
        $macma_str2 = "Executing commands" nocase
        $macma_str3 = "Screen capture" nocase
        $macma_str4 = "Keylogging" nocase
        $macma_str5 = "Audio capture" nocase
        $macma_str6 = "Uploading and downloading files" nocase
    
    condition:
        uint32(0) == 0xCAFEBABE and
        filesize < 500KB and
        ($macma_str1 and $macma_str2 and $macma_str3 and $macma_str4 and $macma_str5 and $macma_str6)
}

rule Macma_Components
{
    meta:
        description = "Detects various components of the Macma backdoor"
        author = "Kadircan Kaya"
        approver = "Yasin Kalli"
        date = "2024-07-26"
        version = "1.0"
        reference = "https://symantec-enterprise-blogs.security.com/threat-intelligence/daggerfly-espionage-updated-toolset"
        copyright = "InfoSEC"
        component1 = "570cd76bf49cf52e0cb347a68bdcf0590b2eaece134e1b1eba7e8d66261bdbe6"
        component2 = "eff1c078895bbb76502f1bbad12be6aa23914a4d208859d848d5f087da8e35e0"
        component3 = "d8a49e688f214553a7525be96cadddec224db19bae3771d14083a2c4c45f28eb"
        component4 = "955cee70c82bb225ca2b108f987fbb245c48eefe9dc53e804bbd9d55578ea3a4"
        component5 = "fce66c26deff6a5b7320842bc5fa8fe12db991efe6e3edc9c63ffaa3cc5b8ced"
    
    strings:
        $component_str1 = "arch"
        $component_str2 = "at"
        $component_str3 = "com.USAgent.mv.plist"
        $component_str4 = "USAgent"
    
    condition:
        uint32(0) == 0xCAFEBABE and
        filesize < 200KB and
        any of ($component_str*)
}

rule Linux_Malware_Daggerfly
{
    meta:
        description = "Detects Linux malware with Daggerfly library"
        author = "Kadircan Kaya"
        approver = "Yasin Kalli"
        date = "2024-07-26"
        version = "1.0"
        reference = "https://symantec-enterprise-blogs.security.com/threat-intelligence/daggerfly-espionage-updated-toolset"
        copyright = "InfoSEC"
        hash1 = "4c3b9a568d8911a2a256fdc2ebe9ff5911a6b2b63c7784da08a4daf692e93c1a"
        hash2 = "ef9aebcd9022080189af8aa2fb0b6594c3dfdc862340f79c17fb248e51fc9929"
        hash3 = "0cabb6780b804d4ee285b0ddb00b02468f91b218bd2db2e2310c90471f7f8e74"
        hash4 = "3894a8b82338791764524fddac786a2c5025cad37175877959a06c372b96ef05"
        hash5 = "3a6605266184d967ab4643af2c73dafb8b7724d21c7aa69e58d78b84ebc06612"
    
    strings:
        $linux_str1 = "Daggerfly"
        $linux_str2 = "modular"
        $linux_str3 = "trojan"
    
    condition:
        uint32(0) == 0x7F454C46 and
        filesize < 1MB and
        any of ($linux_str*)
}

rule Daggerfly_C2_Servers
{
    meta:
        description = "Detects network traffic to known Daggerfly C2 servers"
        author = "Kadircan Kaya"
        approver = "Yasin Kalli"
        date = "2024-07-26"
        version = "1.0"
        reference = "https://symantec-enterprise-blogs.security.com/threat-intelligence/daggerfly-espionage-updated-toolset"
        copyright = "InfoSEC"
        server1 = "103.243.212.98"
        server2 = "103.96.131.150"
        server3 = "103.96.128.44"
    
    strings:
        $ioc1 = "103.243.212.98"
        $ioc2 = "103.96.131.150"
        $ioc3 = "103.96.128.44"
    
    condition:
        any of ($ioc*)
}

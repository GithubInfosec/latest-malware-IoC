rule M_Hunting_Certificate_Gala_lab_corp
{
    meta:
        author = "Mandiant"
        description = "Rule looks for PEs signed using likely stolen certificate issued for Gala Lab corp"
        disclaimer = "This rule is meant for hunting and is not tested to run in a production environment."

    strings:
        $org = "Gala Lab Corp."
        $serial = { 0A 2C BF 9B 18 FE 1B 20 B9 4E CA C4 B0 78 B8 C1 }

    condition:
        ((uint16(0) == 0x5a4d and uint32(uint32(0x3C)) == 0x00004550) 
        or (uint32(0) == 0xE011CFD0 and uint32(4) == 0xE11AB1A1)) 
        and #org > 1 and $serial
}

rule M_Hunting_Certificate_CCR_INC
{
    meta:
        author = "Mandiant"
        description = "Rule looks for PEs signed using likely stolen certificate issued for CCR INC"
        disclaimer = "This rule is meant for hunting and is not tested to run in a production environment."

    strings:
        $org = "CCR INC"
        $serial = { 6F 97 F1 3D A5 5E 9F 70 A6 92 7E D1 B3 3E EE EE }

    condition:
        ((uint16(0) == 0x5a4d and uint32(uint32(0x3C)) == 0x00004550) or 
        (uint32(0) == 0xE011CFD0 and uint32(4) == 0xE11AB1A1)) and #org > 1 
        and $serial
}

rule M_Hunting_Certificate_ALEAN_TOUR
{
    meta:
        author = "Mandiant"
        description = "Rule looks for PEs signed using likely stolen certificate issued for ALEAN-TOUR"
        disclaimer = "This rule is meant for hunting and is not tested to run in a production environment."

    strings:
        $org = "OOO ALEAN-TOUR"
        $serial = { 05 FA 8A 72 DA 46 07 4F DE 1E 34 C7 46 61 EE 00 }

    condition:
        ((uint16(0) == 0x5a4d and uint32(uint32(0x3C)) == 0x00004550) 
        or (uint32(0) == 0xE011CFD0 and uint32(4) == 0xE11AB1A1)) 
        and #org > 1 and $serial
}

rule M_Hunting_Uploader_PINEGROVE_1
{
    meta:
        author = "Mandiant"
        description = "Hunting for PINEGROVE uploader malware family."
        disclaimer = "This rule is meant for hunting and is not tested to run in a production environment."

    strings:
        $s1 = "Config: `%v`" ascii
        $s2 = "auth.json" ascii
        $s3 = "sp=%v%v%x" ascii
        $s4 = "Time: %v" ascii
        $s5 = "/me/drive/root" ascii
        $s6 = "OneDrive" ascii fullword
        $s7 = "microsoft.graph.driveItemUploadableProperties" ascii
        $s8 = "client_id=%v&client_secret=%v" ascii
        $s9 = "http://localhost/onedrive-login" ascii

    condition:
        (
            ((uint32(0) == 0xcafebabe) or (uint32(0) == 0xfeedface) or 
            (uint32(0) == 0xfeedfacf) or (uint32(0) == 0xbebafeca) or 
            (uint32(0) == 0xcefaedfe) or (uint32(0) == 0xcffaedfe)) or 
            (uint32(0) == 0x464c457f) or 
            (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550)
        ) and 
        (6 of them)
}

rule M_Hunting_Uploader_PINEGROVE_2
{
    meta:
        author = "Mandiant"
        description = "Hunting for PINEGROVE uploader malware family."
        disclaimer = "This rule is meant for hunting and is not tested to run in a production environment."

    strings:
        $f1 = "main.AllFiles" ascii
        $f2 = "main.Collect" ascii
        $f3 = "main.ConfigInit" ascii
        $f4 = "main.ConfigRead" ascii
        $f5 = "main.ConfigSave" ascii
        $f6 = "main.ConfigUpdate" ascii
        $f7 = "main.Exit" ascii
        $f8 = "main.FileRange" ascii
        $f9 = "main.FileReader" ascii
        $f10 = "main.FileStatus" ascii
        $f11 = "main.FormatRemoteFilePath" ascii
        $f12 = "main.GetFileName" ascii
        $f13 = "main.GetReomtePath" ascii
        $f14 = "main.Header" ascii
        $f15 = "main.init.0" ascii
        $f16 = "main.InitFile" ascii
        $f17 = "main.IsFolder" ascii
        $f18 = "main.main" ascii
        $f19 = "main.PreLoad" ascii
        $f20 = "main.Range2Int" ascii
        $f21 = "main.RemainTime" ascii
        $f22 = "main.SessionCreate" ascii
        $f23 = "main.ShowBar" ascii
        $f24 = "main.StringChecker" ascii
        $f25 = "main.Task" ascii
        $f26 = "main.TaskFail" ascii
        $f27 = "main.ThreadUpload" ascii
        $f28 = "main.Timer" ascii
        $f29 = "main.TimeUnix" ascii
        $f30 = "main.Upload" ascii
        $f31 = "main.Upload.func1" ascii
        $f32 = "main.Uploading" ascii
        $version = "go1.13.1"

    condition:
        (
            ((uint32(0) == 0xcafebabe) or (uint32(0) == 0xfeedface) or 
            (uint32(0) == 0xfeedfacf) or (uint32(0) == 0xbebafeca) or 
            (uint32(0) == 0xcefaedfe) or (uint32(0) == 0xcffaedfe)) or 
            (uint32(0) == 0x464c457f) or 
            (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550)
        ) and 
        $version and (25 of ($f*))
}

rule M_Hunting_Uploader_PINEGROVE_3
{
    meta:
        author = "Mandiant"
        description = "Hunting for PINEGROVE uploader malware family."
        disclaimer = "This rule is meant for hunting and is not tested to run in a production environment."

    strings:
        $s1 = "RefreshToken"
        $s2 = "RefreshInterval"
        $s3 = "ThreadNum"
        $s4 = "BlockSize"
        $s5 = "SigleFile"
        $s6 = "MainLand"
        $s7 = "MSAccount"
        $anchor1 = "driveItemUploadableProperties"
        $anchor2 = "client_id"
        $anchor3 = "client_secret"
        $anchor4 = "onedrive-login"
        $anchor5 = "authorization_code"

    condition:
        (
            ((uint32(0) == 0xcafebabe) or (uint32(0) == 0xfeedface) or 
            (uint32(0) == 0xfeedfacf) or (uint32(0) == 0xbebafeca) or 
            (uint32(0) == 0xcefaedfe) or (uint32(0) == 0xcffaedfe)) or 
            (uint32(0) == 0x464c457f) or 
            (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550)
        ) and 
        (5 of ($s*)) and 
        (4 of ($anchor*))
}

import "elf"

rule M_Hunting_Utility_Linux_SQLULDR2_1
{
    meta:
        author = "Mandiant"
        description = "Detection of the Linux version of SQLULDR2."
        disclaimer = "This rule is meant for hunting and is not tested to run in a production environment."

    strings:
        $name = "sqluldr2zip.c" ascii
        $out = "uldrdata.%p.txt" ascii
        $heading = "SQL*UnLoader: Fast Oracle Text Unloader" ascii
        $p1 = "exec    = the command to execute the SQLs" ascii
        $p2 = "file    = output file name(default: uldrdata.txt)" ascii
        $p3 = "format  = MYSQL: MySQL Insert SQLs, SQL: Insert SQLs" ascii
        $p4 = "text    = output type (MYSQL, CSV, MYSQLINS, ORACLEINS, FORM, SEARCH)" ascii
        $p5 = "rows    = print progress for every given rows (default, 1000000)" ascii
        $p6 = "query   = select statement" ascii
        $p7 = "user    = username/password@tnsname" ascii

    condition:
        (uint32(0) == 0x464c457f) and 
        $name and $out and $heading and (5 of ($p*)) and
        for any i in (0 .. elf.symtab_entries): 
        (elf.symtab[i].name == "OCIServerAttach") and
        for any i in (0 .. elf.symtab_entries): 
        (elf.symtab[i].name == "OCISessionBegin")
}

import "pe"
import "elf"

rule M_Hunting_Utility_SQLULDR2_1
{
    meta:
        author = "Mandiant"
        description = "Detection of SQLULDR2."
        disclaimer = "This rule is meant for hunting and is not tested to run in a production environment."

    strings:
        $win_name = "sqluldr2.exe" ascii
        $elf_name = "sqluldr2zip.c" ascii
        $out = "uldrdata.%p.txt" ascii
        $heading = "SQL*UnLoader: Fast Oracle Text Unloader" ascii
        $p1 = "exec    = the command to execute the SQLs" ascii
        $p2 = "file    = output file name(default: uldrdata.txt)" ascii
        $p3 = "format  = MYSQL: MySQL Insert SQLs, SQL: Insert SQLs" ascii
        $p4 = "text    = output type (MYSQL, CSV, MYSQLINS, ORACLEINS, FORM, SEARCH)" ascii
        $p5 = "rows    = print progress for every given rows (default, 1000000)" ascii
        $p6 = "query   = select statement" ascii
        $p7 = "user    = username/password@tnsname" ascii
        $import = "OCI.dll" ascii

    condition:
        (((uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and 
        pe.imports("OCI.dll", "OCIServerAttach") and
        pe.imports("OCI.dll", "OCISessionBegin") and
        $import and $win_name and
        for all of ($p*) : ( @ > @heading )) or 
        ((uint32(0) == 0x464c457f) and 
        $elf_name and
        for any i in (0 .. elf.symtab_entries): 
        (elf.symtab[i].name == "OCIServerAttach") and
        for any i in (0 .. elf.symtab_entries): 
        (elf.symtab[i].name == "OCISessionBegin"))) and 
        $out and $heading and (5 of ($p*))
}

rule M_Hunting_Dropper_DUSTTRAP_1
{
    meta:
        author = "Mandiant"
        description = "Detects the DUSTTRAP dropper (x64) based on the use of CFG patching constants and argument construction for payload entry-point."
        disclaimer = "This rule is meant for hunting and is not tested to run in a production environment."

    strings:
        $cfg_patch_constant_1 = { 48 FF E0 CC 90 }
        $cfg_patch_constant_2 = { 8B DA 48 8B F9 E8 }
        $cfg_patch_constant_3 = { B8 48 8B 00 00 66 39 02 }
        $cfg_patch_constant_4 = { 81 7A 07 48 8B D1 48 }

        $log_format = "%lld.log" wide

    condition:
        uint16(0) == 0x5a4d and
        all of ($cfg_patch_constant_*) and
        $log_format
}

import "pe"

rule M_Hunting_DUSTPAN_CryptKeys
{
    meta:
        author = "Mandiant"
        description = "Attempts to detect executables containing known DUSTPAN encryption keys within the .data section."
        disclaimer = "This rule is meant for hunting and is not tested to run in a production environment."

    strings:
        $key_1 = { 3BCF741BF6411C087415BA340000004C8D05F28C0000488B4910E801F0FEFFB8 }
        $key_2 = { C4498BD6488BCFE848A5000084C07564488BCFE8585C0000498B0F4C8B497045 }
        $key_3 = { A24299055F1F0C14CBDD0B01DFA64C34F5FD033CA7F1AF30A0C75C57359D41E0 }

    condition:
        filesize < 15MB and
        for any i in (0..pe.number_of_sections - 1): (
            pe.sections[i].name == ".data" and
            any of ($key_*) in (pe.sections[i].raw_data_offset..
            pe.sections[i].raw_data_offset + pe.sections[i].raw_data_size)
        )
}

import "pe"
 
rule M_HUNTING_DUSTTRAP_PayloadFile
{
    meta:
        author = "Mandiant"
        description = "Detects executables containing a .lrsrc section which may represent DUSTTRAP payloads."
        disclaimer = "This rule is meant for hunting and is not tested to run in a production environment."

    condition:
        for any i in (0..pe.number_of_sections - 1): (
            uint32(pe.sections[i].raw_data_offset + 0) == 0x100 and
            pe.sections[i].raw_data_size > uint32(pe.sections[i].raw_data_offset + 0) and
            pe.sections[i].name == ".lrsrc" and
            uint32(pe.sections[i].raw_data_offset + 4) < 0x1000 and
            uint32(pe.sections[i].raw_data_offset + 8) < 4
        )
}

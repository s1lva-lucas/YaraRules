rule MSI_Powershell_BatLoader
{
    meta:
        description = "Regla Yara para detectar archivos MSI sospechosos que invocan a Powershell"
        author = "German Fernandez | CronUp - Cyber Threat Intelligence"
        reference = "https://twitter.com/1ZRR4H/status/1575364101148114944"
        date = "2022-10-13"
        hash = "08cd62a04c3ed5245f022424e9843d6e420ce6e2431c0fecd7c90a63b2a81c45"

    strings:
        $magic = {D0 CF 11 E0 A1 B1 1A E1} // .MSI
        $s1 = {70 6f 77 65 72 73 68 65 6c 6c 2e 65 78 65} // powershell.exe
        $s2 = {70 77 73 68 2e 65 78 65} // pwsh.exe
        $s3 = {53 74 61 72 74 2d 50 72 6f 63 65 73 73} // Start-Process
        $m1 = {49 6e 76 6f 6b 65 2d 57 65 62 52 65 71 75 65 73 74} // Invoke-WebRequest
        $m2 = {49 6e 76 6f 6b 65 2d 52 65 73 74 4d 65 74 68 6f 64} // Invoke-RestMethod
        
    condition:
        ($magic at 0) and all of ($s*) and 1 of ($m*)
}

rule MSI_Powershell_BatLoader2
{
    meta:
        description = "Yara Rule for BATLOADER Dropping avolkov.exe"
        author = "Lucas Silva"
        date = "2022-10-26"
        hash = "4a3c2509c588b11e9bc2fdb42c1846b126cc24778dc99be051f87f32c5a663d5"

    strings:
        $magic = {D0 CF 11 E0 A1 B1 1A E1} // .MSI
		$s1 = {53 65 74 75 70 50 72 6F 6A 65 63 74 31} //SetupProject1
        $s2 = {61 76 6F 6C 6B 6F 76 2E 65 78 65}// avolkov.exe

    condition:
        ($magic at 0) and all of ($s*) 
}

rule MSI_Powershell_BatLoader_signed
{
    meta:
        description = "Yara Rule for BATLOADER Dropping avolkov.exe"
        author = "Lucas Silva"
        date = "2022-10-26"
        hash = "8f53af0d8f71f536afaee332fa701555d4bb64fbf9efd85c644ed14f0671524b"
        hash = "026a02f15e27bf5d15baefee6306a0e03876193717b946fc82f83f40b486f598"

    strings:
        $magic = {D0 CF 11 E0 A1 B1 1A E1} // .MSI
		$s1 = {53 65 74 75 70 50 72 6F 6A 65 63 74 31} //SetupProject1
        $s2 = {61 76 6F 6C 6B 6F 76 2E 65 78 65}// avolkov.exe
        $m1 = {53 75 70 65 72 6C 61 74 69 76 61 20 53 70} // Signer: Superlativa Sp
        $m2 = {54 61 78 20 49 6E 20 43 6C 6F 75 64} // Signer: Tax In Cloud sp. z o. o.

    condition:
        ($magic at 0) and all of ($s*) and 1 of ($m*) 
}
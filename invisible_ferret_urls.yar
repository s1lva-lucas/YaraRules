rule invisible_ferret_urls_from_js_malware {
    meta:
        description = "Detects invisible ferret C2 on port 1224"
        author = "Lucas Silva"
        date = "2023-09-20"
        reference = "Internal monitoring"
        hash = ""

    strings:
        $s1 = ":1224/client/" nocase
        $s2 = ":1224/uploads/" nocase
        $s3 = ":1224/pdown" nocase
        $s4 = ":1224/brow/" nocase
        $s5 = ":1224/keys" nocase
        $s6 = ":1224/payload/" nocase
        $s7 = ":1224/mclip" nocase

    condition:
        any of them
}
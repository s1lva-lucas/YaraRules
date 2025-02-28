rule invisible_ferret_urls_from_js_malware {
    meta:
        description = "Detects invisible ferret C2 on ports multiple ports"
        author = "Lucas Silva"
        date = "2025-02-28"
        reference = "Internal monitoring"
        version = "1.3"
    strings:
        // All C2 URL patterns
        $c2_1224 = /:1224\/(client|uploads|pdown|brow|keys|payload|mclip|api\/clip)/ nocase
        $c2_1244 = /:1244\/(client|uploads|pdown|brow|keys|payload|mclip|api\/clip)/ nocase
        $c2_2245 = /:2245\/(client|uploads|pdown|brow|keys|payload|mclip|api\/clip)/ nocase
        $c2_3000 = /:3000\/(client|uploads|pdown|brow|keys|payload|mclip|api\/clip)/ nocase
        $c2_3001 = /:3001\/(client|uploads|pdown|brow|keys|payload|mclip|api\/clip)/ nocase
        $c2_1245 = /:1245\/(client|uploads|pdown|brow|keys|payload|mclip|api\/clip)/ nocase
        $c2_5000 = /:5000\/(pdown|brow|keys|mclip|api\/clip)/ nocase // denoise
        $c2_5001 = /:5001\/(pdown|brow|keys|mclip|api\/clip)/ nocase // denoise
    condition:
        any of them
}
import "vt"

rule invisible_ferret_urls
{
  meta:
    author = "Lucas Silva"
    description = "Detects Invisible Ferret/Beaver Tail URLs" 
    target_entity = "url"
    date = "2025-02-28"
    version = "1.1"
    severity = "high"
    confidence = "medium"
  
  condition:
    vt.net.url.new_url and
    (
        // Suspicious ports
        (
            vt.net.url.port == 1224 or 
            vt.net.url.port == 1244 or
            vt.net.url.port == 1245 or
            vt.net.url.port == 3000 or
            vt.net.url.port == 5000
        )
        and
        // Suspicious paths
        (
          vt.net.url.path icontains "/client/" or
          vt.net.url.path icontains "/uploads" or 
          vt.net.url.path icontains "/pdown" or
          vt.net.url.path icontains "/brow/" or
          vt.net.url.path icontains "/keys" or
          vt.net.url.path icontains "/payload/" or
          vt.net.url.path icontains "/mclip" or 
          vt.net.url.path icontains "/api/clip"
        )
    ) or (vt.net.url.path icontains "/pdown" and 
    (vt.net.url.port == 80 or not vt.net.url.port)
    )
}
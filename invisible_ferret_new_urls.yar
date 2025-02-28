import "vt"

rule invisible_ferret_new_urls
{
  meta:
    author = "Analyst Name" // Add your name
    description = "Detects suspicious URLs with specific path patterns" // Add a meaningful description
    target_entity = "url"
  
  condition:
    vt.net.url.new_url and
    vt.net.url.port == 1224 and
    (
      vt.net.url.path icontains "/client/" or
      vt.net.url.path icontains "/uploads/" or 
      vt.net.url.path icontains "/pdown" or
      vt.net.url.path icontains "/brow/" or
      vt.net.url.path icontains "/keys" or
      vt.net.url.path icontains "/payload/" or
      vt.net.url.path icontains "/mclip"
    )
}
rule wncld_extension_dropper
{
    strings:
        $ = "[System.Reflection.Assembly]::LoadWithPartialName(\"System.Web.Extensions\")" ascii nocase
        $ = "$uid = " ascii nocase
        $ = "New-Object system.Net.WebClient;"
        $ = "downloadString(" ascii nocase
        $ = "Invoke-Expression" ascii nocase
		
    condition:
        filesize < 500KB and all of them
}

rule wncld_manifest
{
    strings:
        $ = "\"devtools_page\":\"devtools.html\"" ascii nocase
        $ = "\"content_scripts\":" ascii nocase
        $ = "content.js" ascii nocase
        $ = "\"matches\": [\"<all_urls>\"]" ascii nocase
        $ = "\"run_at\": \"document_idle\"" ascii nocase
        $ = "extensions_page.js" ascii nocase
        $ = "\"matches\": [\"chrome://extensions/*\"]" ascii nocase
        $ = "\"permissions\":" ascii nocase
        $ = "unsafe-eval" ascii nocase
        $ = "storage" ascii nocase
        $ = "webRequestBlocking" ascii nocase	

    condition:
        uint16(0) == 0xa7b
                and
                filesize < 1500KB
                and
                all of them
}
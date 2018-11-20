rule phishing_pdf : PDF
{
        meta:
		            author = "Alvosec Security Team <info@alvosec.com>"
		            description = "Detect VBA macro code in Office document"
		            date = "2018-19-11"
		            filetype = "Office documents"

        strings:
                $header = "%PDF-1"
                $url = "URI(http" // take this as an experimental rule, because it will list also non-phishing websites.
                $url2 = "URI (http"

        condition:
                ($header) and ($url or $url2)
}

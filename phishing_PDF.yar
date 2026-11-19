rule phishing_pdf : PDF
{
        meta:
		author = "Alvosec Security Team <info@alvosec.com>"
		description = "Detect PDF files containing external URI links (experimental, phishing hunting)"
		date = "2018-19-11"
		filetype = "PDF"

        strings:
                $header = "%PDF-1"
                $url = "URI(http" // take this as an experimental rule, because it will list also non-phishing websites.
                $url2 = "URI (http"

        condition:
                ($header) and ($url or $url2)
}

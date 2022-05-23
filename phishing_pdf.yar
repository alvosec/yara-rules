rule phishing_pdf : PDF
{
        meta:
                author = "Alvosec Security (@alvosec)"
                version = "0.1"

        strings:
                $header = "%PDF-1"
                $url = "URI(http"
                $url2 = "URI (http"

        condition:
                ($header) and ($url or $url2)
}

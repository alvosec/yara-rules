rule barc0de
{
        meta:
                author = "Alvosec Security Team <info@alvosec.com>"
                description = "barc0de"
                date = "2018-28-11"
                filetype = "PHP files"

        strings:
                $a = "barc0de mini 2.1"
                $b = "md5_pass"
                $c = "Ly9sb2dpbiBwYWdlDQpAc2Vzc2lvbl9zd"

        condition:
                all of them
}

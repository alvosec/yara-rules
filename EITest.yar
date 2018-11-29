rule EITest
{
        meta:
		author = "Alvosec Security Team <info@alvosec.com>"
		description = "EITest simple test"
		date = "2018-28-11"
		filetype = "PHP files"

        strings:
		$a = "?php"
		$b = "= explode(chr(("

        condition:
                all of them
}

rule scanconfig
{
        meta:
        author = "Alvosec Security Team <info@alvosec.com>"
        description = "Scanconfig"
        date = "2018-28-11"
	filetype = "PHP files"

        strings:
		$a = "Lumajangcrew And All Forum Hacker Indonesia" fullword ascii
		$b = "eval(base64_decode($scanconfig))" fullword ascii

        condition:
                all of them
}

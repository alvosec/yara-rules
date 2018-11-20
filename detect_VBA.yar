rule VBA_macro_code
{
	meta:
		author = "Alvosec Security Team <info@alvosec.com>"
		description = "Detect VBA macro code in Office document"
		date = "2018-19-11"
		filetype = "Office documents"

	strings:
		$word_document = "<?mso-application progid=\"Word.Document\"?"
		$macrospresent = "w:macrosPresent=\"yes\""
		$editdata = "editdata.mso"

	condition:
		all of them
}

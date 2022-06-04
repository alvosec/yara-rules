rule Follina_CVE_2022_30190
{	
	meta:
		author = "Joe Security"
		reference = "https://doublepulsar.com/follina-a-microsoft-office-code-execution-vulnerability-1a47fce5629e" 
	strings:
		$msdt1 = "ms-msdt:/id" ascii wide nocase
        $msdt2 = "ms-msdt:-id" ascii wide nocase
        $para1 = "IT_RebrowseForFile" ascii wide nocase
        							
	condition:
		(1 of ($msdt*) and 1 of ($para*))
}

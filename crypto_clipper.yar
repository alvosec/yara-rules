rule CRYPTO_Clipper_Wallet_Address_Swapper
{
    meta:
        author = "Alvosec Security Team <info@alvosec.com>"
        description = "Detects clipboard hijackers (clippers) that watch the clipboard for cryptocurrency addresses and swap them for attacker-controlled ones"
        date = "2026-11-19"
        version = "1.0"
        category = "crypto-malware"
        filetype = "Windows PE"

    strings:
        // Native clipboard API
        $api1 = "OpenClipboard" ascii
        $api2 = "GetClipboardData" ascii
        $api3 = "SetClipboardData" ascii
        $api4 = "AddClipboardFormatListener" ascii
        $api5 = "EmptyClipboard" ascii

        // .NET clipboard access
        $net1 = "Clipboard" ascii wide fullword
        $net2 = "SetText" ascii wide
        $net3 = "GetText" ascii wide

        // Embedded address-matching regexes (BTC / ETH / TRX / LTC / XMR)
        $re1 = "[a-zA-HJ-NP-Z0-9]{25," ascii wide
        $re2 = "[a-km-zA-HJ-NP-Z1-9]{" ascii wide
        $re3 = "[1-9A-HJ-NP-Za-km-z]{" ascii wide
        $re4 = "0x[a-fA-F0-9]{40}" ascii wide
        $re5 = "0x[0-9a-fA-F]{40}" ascii wide
        $re6 = "T[A-Za-z1-9]{33}" ascii wide
        $re7 = "(bc1|[13])" ascii wide
        $re8 = "bc1q[a-z0-9]{" ascii wide

    condition:
        uint16(0) == 0x5A4D and filesize < 15MB and
        ( 3 of ($api*) or all of ($net*) ) and
        2 of ($re*)
}

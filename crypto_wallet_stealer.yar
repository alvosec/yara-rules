rule CRYPTO_Wallet_Stealer_Extension_And_Desktop_Targets
{
    meta:
        author = "Alvosec Security Team <info@alvosec.com>"
        description = "Detects infostealers (PE, script or packaged JS/Python) that target browser wallet extensions and desktop cryptocurrency wallet storage"
        date = "2026-11-19"
        version = "1.0"
        category = "crypto-malware"
        filetype = "Any"

    strings:
        // Chromium wallet extension IDs
        $ext_metamask  = "nkbihfbeogaeaoehlefnkodbefgpgknn" ascii wide
        $ext_phantom   = "bfnaelmomeimhlpmgjnjophhpkkoljpa" ascii wide
        $ext_coinbase  = "hnfanknocfeofbddgcijnmhnfnkdnaad" ascii wide
        $ext_tronlink  = "ibnejdfjmmkpcnlpebklmnkoeoihofec" ascii wide
        $ext_binance   = "fhbohimaelbohpjbbldcngcnapndodjp" ascii wide
        $ext_ronin     = "fnjhmkhhmkbjkkabndcnnogagogbneec" ascii wide
        $ext_trust     = "egjidjbpglichdcondbcbdnbeeppgdph" ascii wide
        $ext_exodusw3  = "aholpfdialjgjfhomihkjbmgjidlcdno" ascii wide
        $ext_keplr     = "dmkamcknogkgcdfhhbddcghachkejeap" ascii wide
        $ext_okx       = "mcohilncbfahbmgdjkbpemcciiolgcge" ascii wide
        $ext_rabby     = "acmacodkjbdgmoleebolmdjonilkdbch" ascii wide

        // Desktop wallet storage locations
        $d_exodus    = "exodus.wallet" ascii wide nocase
        $d_electrum1 = "Electrum\\wallets" ascii wide nocase
        $d_electrum2 = "Electrum/wallets" ascii wide nocase
        $d_atomic1   = "atomic\\Local Storage\\leveldb" ascii wide nocase
        $d_atomic2   = "atomic/Local Storage/leveldb" ascii wide nocase
        $d_eth1      = "Ethereum\\keystore" ascii wide nocase
        $d_eth2      = "Ethereum/keystore" ascii wide nocase
        $d_coinomi   = "Coinomi\\wallets" ascii wide nocase
        $d_jaxx      = "com.liberty.jaxx" ascii wide nocase
        $d_core      = "wallet.dat" ascii wide fullword

    condition:
        filesize < 25MB and
        (
            4 of ($ext_*) or
            ( 2 of ($ext_*) and 2 of ($d_*) ) or
            4 of ($d_*)
        )
}

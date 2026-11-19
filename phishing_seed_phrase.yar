rule PHISH_Crypto_Seed_Phrase_Harvester_HTML
{
    meta:
        author = "Alvosec Security Team <info@alvosec.com>"
        description = "Detects phishing pages that impersonate a crypto wallet and collect the victim's recovery (seed) phrase or private key, then send it to Telegram, Discord or a PHP collector"
        date = "2026-11-19"
        version = "1.0"
        category = "phishing"
        filetype = "HTML"

    strings:
        $html1 = "<html" ascii wide nocase
        $html2 = "<!doctype html" ascii wide nocase

        $p1 = "recovery phrase" ascii wide nocase
        $p2 = "seed phrase" ascii wide nocase
        $p3 = "mnemonic" ascii wide nocase
        $p4 = /(12|24)[ -]word/ nocase
        $p5 = "private key" ascii wide nocase
        $p6 = "secret phrase" ascii wide nocase

        $brand1 = "MetaMask" ascii wide nocase
        $brand2 = "Trust Wallet" ascii wide nocase
        $brand3 = "Phantom" ascii wide nocase
        $brand4 = "Ledger" ascii wide nocase
        $brand5 = "Trezor" ascii wide nocase
        $brand6 = "Coinbase Wallet" ascii wide nocase
        $brand7 = "Exodus" ascii wide nocase
        $brand8 = "WalletConnect" ascii wide nocase

        // An input field asking for the phrase
        $input = /<(input|textarea)[^>]{0,300}(phrase|seed|mnemonic|private.?key)/ nocase

        $x1 = "api.telegram.org/bot" ascii wide
        $x2 = "discord.com/api/webhooks" ascii wide
        $x3 = /action\s*=\s*["'][^"']{0,200}\.php["']/ nocase
        $x4 = /fetch\(\s*["'][^"']{0,200}\.php["']/ nocase

    condition:
        filesize < 5MB and
        any of ($html*) and
        2 of ($p*) and
        any of ($brand*) and
        $input and
        any of ($x*)
}

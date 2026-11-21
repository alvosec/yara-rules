/*
   XPR Network / WebAuth / Metal X phishing rules

   Why: the existing crypto rules in this repo look for Ethereum, Solana and
   Bitcoin wallets (MetaMask, Phantom, Ledger, ...). XPR Network accounts are
   protected by WebAuth and use "PVT_K1_" private keys and on-chain
   permissions, so look-alike Metal X / WebAuth pages slip past them.

   Three rules:
     1. a page that asks for an XPR private key or recovery phrase and sends it away
     2. a page that uses the XPR sign-in kit to ask the victim to sign a
        permission change (updateauth / linkauth), which hands the account over
     3. a page that names a known Metal X look-alike domain
*/

rule PHISH_XPR_WebAuth_Key_Harvester_HTML
{
    meta:
        author = "Dan Gerbot"
        description = "Detects phishing pages that impersonate Metal X, WebAuth or an XPR Network wallet and collect the victim's private key (PVT_K1_ / 5...) or recovery phrase, then send it to Telegram, Discord or a PHP / form collector"
        date = "2026-11-20"
        version = "1.0"
        category = "phishing"
        filetype = "HTML / JavaScript"

    strings:
        $html1 = "<html" ascii wide nocase
        $html2 = "<!doctype html" ascii wide nocase

        // XPR Network brands
        $b1 = "Metal X" ascii wide nocase
        $b2 = "metalx" ascii wide nocase
        $b3 = "WebAuth" ascii wide nocase
        $b4 = "XPR Network" ascii wide nocase
        $b5 = "XPR Wallet" ascii wide nocase
        $b6 = "Proton Wallet" ascii wide nocase

        // What the page asks for
        $p1 = "private key" ascii wide nocase
        $p2 = "recovery phrase" ascii wide nocase
        $p3 = "backup phrase" ascii wide nocase
        $p4 = "secret phrase" ascii wide nocase
        $p5 = "seed phrase" ascii wide nocase
        $p6 = "mnemonic" ascii wide nocase

        // XPR / Antelope private key formats checked in the page's own script
        $k1 = "PVT_K1_" ascii wide
        $k2 = "^5[HJK]" ascii wide

        // An input box asking for a key or phrase
        $input = /<(input|textarea)[^>]{0,300}(phrase|seed|mnemonic|private.?key|pvt|wif|recovery)/ nocase

        // Where the stolen key is sent
        $x1 = "api.telegram.org/bot" ascii wide
        $x2 = "discord.com/api/webhooks" ascii wide
        $x3 = "discordapp.com/api/webhooks" ascii wide
        $x4 = /action\s*=\s*["'][^"']{0,200}\.php["']/ nocase
        $x5 = /fetch\(\s*["'][^"']{0,200}\.php["']/ nocase
        $x6 = "formsubmit.co/" ascii wide nocase
        $x7 = "getform.io/f/" ascii wide nocase

    condition:
        filesize < 5MB and
        any of ($html*) and
        any of ($b*) and
        any of ($x*) and
        (
            ( $input and any of ($p*) ) or
            ( any of ($k*) and any of ($p*) )
        )
}

rule PHISH_XPR_WebAuth_Permission_Hijack_JS
{
    meta:
        author = "Dan Gerbot"
        description = "Detects pages that use the XPR Network / WebAuth sign-in kit (Proton Web SDK) to ask the visitor to sign an account permission change (updateauth or linkauth) behind a Metal X, lending, airdrop or reward lure. Signing it hands control of the account to the attacker. Note: genuine permission-management tools also build updateauth actions; the lure words keep those out"
        date = "2026-11-20"
        version = "1.0"
        category = "phishing"
        filetype = "HTML / JavaScript"

    strings:
        // XPR sign-in kit (Proton Web SDK / WebAuth)
        $sdk1 = "ProtonWebSDK" ascii wide
        $sdk2 = "proton-web-sdk" ascii wide
        $sdk3 = "@proton/web-sdk" ascii wide
        $sdk4 = "webauth.com" ascii wide nocase
        $sdk5 = "@proton/link" ascii wide

        // A permission-change action written into the page
        $act = /["']?name["']?\s*:\s*["'](updateauth|linkauth)["']/ nocase

        // Lures
        $l1 = "Metal X" ascii wide nocase
        $l2 = "metalx" ascii wide nocase
        $l3 = "airdrop" ascii wide nocase
        $l4 = "claim reward" ascii wide nocase
        $l5 = "claim your" ascii wide nocase
        $l6 = "verify your account" ascii wide nocase
        $l7 = "verify wallet" ascii wide nocase
        $l8 = "lending" ascii wide nocase

    condition:
        filesize < 10MB and
        any of ($sdk*) and
        $act and
        any of ($l*)
}

rule PHISH_XPR_MetalX_Lookalike_Domain
{
    meta:
        author = "Dan Gerbot"
        description = "Detects web pages or scripts that use the XPR sign-in kit together with a known Metal X look-alike domain (metalx.live, used in the October 2026 Metal X Lending account takeovers) or a common misspelling of metalx. The genuine site is metalx.com"
        date = "2026-11-20"
        version = "1.0"
        category = "phishing"
        filetype = "HTML / JavaScript"

    strings:
        $sdk1 = "ProtonWebSDK" ascii wide
        $sdk2 = "proton-web-sdk" ascii wide
        $sdk3 = "@proton/web-sdk" ascii wide
        $sdk4 = "webauth" ascii wide nocase
        $sdk5 = "@proton/link" ascii wide

        $d1 = "metalx.live" ascii wide nocase
        $d2 = /(rnetalx|metallx|meta1x|metaix|metalxx)\.[a-z]{2,8}/ nocase

    condition:
        filesize < 10MB and
        any of ($sdk*) and
        any of ($d*)
}

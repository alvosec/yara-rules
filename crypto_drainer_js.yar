rule CRYPTO_Web3_Wallet_Drainer_Kit_JS
{
    meta:
        author = "Alvosec Security Team <info@alvosec.com>"
        description = "Detects Web3 wallet drainer kits: JavaScript that connects a wallet, requests unlimited token/NFT approvals or Permit2 signatures, and reports victims to Telegram or Discord"
        date = "2026-11-19"
        version = "1.0"
        category = "crypto-drainer"
        filetype = "JavaScript / HTML"

    strings:
        // Wallet connection / signing
        $w1 = "eth_requestAccounts" ascii wide
        $w2 = "wallet_switchEthereumChain" ascii wide
        $w3 = "eth_signTypedData_v4" ascii wide
        $w4 = "window.ethereum" ascii wide
        $w5 = "solana.connect" ascii wide
        $w6 = "signAllTransactions" ascii wide

        // Approval / transfer abuse
        $a1 = "setApprovalForAll" ascii wide
        $a2 = "increaseAllowance" ascii wide
        $a3 = "0x000000000022D473030F116dDEE9F6B43aC78BA3" ascii wide nocase // Uniswap Permit2
        $a4 = "PermitBatch" ascii wide
        $a5 = "0x095ea7b3" ascii wide nocase   // approve(address,uint256)
        $a6 = "0xa22cb465" ascii wide nocase   // setApprovalForAll(address,bool)
        $a7 = "0x39509351" ascii wide nocase   // increaseAllowance(address,uint256)
        $a8 = "115792089237316195423570985008687907853269984665640564039457584007913129639935" ascii wide // MaxUint256
        $a9 = "0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff" ascii wide nocase
        $a10 = "transferFrom" ascii wide

        // Victim reporting / exfiltration
        $x1 = "api.telegram.org/bot" ascii wide
        $x2 = "discord.com/api/webhooks" ascii wide
        $x3 = "discordapp.com/api/webhooks" ascii wide

    condition:
        filesize < 10MB and
        2 of ($w*) and
        3 of ($a*) and
        any of ($x*)
}

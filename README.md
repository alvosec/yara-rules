# Alvosec YARA Rules

YARA rules by **Alvosec Security Team** and the community for detecting crypto malware,
wallet drainers, phishing kits, webshells and other threats.

## Rules

| File | Rule | Detects |
|---|---|---|
| `crypto_clipper.yar` | `CRYPTO_Clipper_Wallet_Address_Swapper` | Clipboard hijackers that swap crypto addresses (native and .NET) |
| `crypto_wallet_stealer.yar` | `CRYPTO_Wallet_Stealer_Extension_And_Desktop_Targets` | Stealers targeting wallet extensions (MetaMask, Phantom, ...) and desktop wallets |
| `crypto_drainer_js.yar` | `CRYPTO_Web3_Wallet_Drainer_Kit_JS` | Web3 drainer kits: unlimited approvals / Permit2 plus Telegram or Discord reporting |
| `phishing_seed_phrase.yar` | `PHISH_Crypto_Seed_Phrase_Harvester_HTML` | Fake wallet pages that harvest recovery phrases |
| `phishing_PDF.yar` | `phishing_pdf` | PDFs with external URI links (experimental) |
| `short_url.yar` | `short_url` | URL shortener domains |
| `tor_adr.yar` | `tor_address` | Tor `.onion` URLs |
| `php_sus.yar` | `php_suspicious` | Suspicious PHP / webshell indicators |
| `barc0de.yar`, `EITest.yar`, `scanconfig.yar` | | PHP webshells and injections |
| `detect_VBA.yar` | `VBA_macro_code` | Office XML documents with macros |
| `follina.yar` | `Follina_CVE_2022_30190` | Follina (MSDT) exploit documents (Joe Security) |
| `mars_stealer.yar` | `infostealer_win_mars_stealer_early_version` | Mars Stealer (SEKOIA.IO) |

## Usage

```bash
# scan a directory with all rules
yara -r crypto_drainer_js.yar /var/www

# compile everything once, then scan fast
yarac *.yar alvosec.yarc
yara -r -C alvosec.yarc /path/to/scan
```

## Contributing

New rules and improvements are welcome. Fork the repo, add your rule, and open a
**pull request**. See [CONTRIBUTING.md](CONTRIBUTING.md) for the rule format and how to test.

## License

[Detection Rule License (DRL) 1.1](LICENSE). Free to use, including commercially, as long as
you keep the rule author attribution.

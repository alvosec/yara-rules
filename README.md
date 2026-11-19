# Alvosec YARA Rules

YARA rules by **Alvosec Security Team** and the community for detecting crypto malware,
wallet drainers, phishing kits, webshells and other threats.

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

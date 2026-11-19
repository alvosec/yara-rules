# Contributing to Alvosec YARA Rules

Thanks for helping! Anyone can propose new rules or improvements through a **pull request**.
You don't need any special access to this repository.

## How it works (fork & pull request)

1. **Fork** this repository (button at the top right on GitHub).
2. **Clone** your fork and create a branch:
   ```bash
   git clone https://github.com/<your-username>/yara-rules.git
   cd yara-rules
   git checkout -b add-<family>-rule
   ```
3. **Add your rule** as a new `.yar` file (one topic per file), e.g. `crypto_myfamily.yar`.
4. **Test it** (see below).
5. **Commit and push** to your fork, then open a **Pull Request** against `master`.
6. A GitHub Action compiles all rules automatically. Alvosec Security Team reviews the rule,
   may ask for changes, and merges it when it is ready.

Not comfortable with pull requests? Open an **Issue** with the rule text and a sample hash.

## Rule requirements

```yara
rule CATEGORY_Family_Short_Description
{
    meta:
        author = "Your Name or Handle"
        description = "What this detects and why"
        date = "YYYY-MM-DD"
        version = "1.0"
        reference = "https://link-to-report-or-sample"   // recommended
        hash = "sha256 of a sample it matches"           // recommended

    strings:
        $s1 = "..." ascii wide

    condition:
        uint16(0) == 0x5A4D and filesize < 5MB and all of them
}
```

- **Naming:** `CATEGORY_Family_Short_Description`. Categories: `CRYPTO`, `PHISH`, `WEBSHELL`,
  `MAL`, `EXPL`, `HKTL`, `SUSP`.
- **Required meta:** `author`, `description`, `date` (YYYY-MM-DD). The CI checks for these.
- **Unique rule names.** Duplicate names break compilation for everyone.
- **Keep it tight:** add a file type check (`uint16(0) == 0x5A4D`, `<?php`, `<html`, etc.)
  and a `filesize` limit when possible. Avoid single generic strings.
- **Credit others:** if the rule is based on someone else's work, keep their `author`
  and add a `reference`.

## Testing your rule

```bash
# 1. Syntax check (also check it compiles together with all existing rules)
yarac your_rule.yar /dev/null
yarac *.yar /dev/null

# 2. It should match the malicious sample
yara -s your_rule.yar /path/to/sample

# 3. It should NOT match clean files
yara -r your_rule.yar /usr /opt C:\\Windows\\System32   # whatever is relevant
```

## Please do NOT

- Upload live malware to this repo. Share a SHA256 hash or a public reference
  (VirusTotal, MalwareBazaar, a vendor report) instead.
- Include credentials, personal data, or private customer information.

## License

By submitting a pull request you agree that your contribution is published under the
[Detection Rule License (DRL) 1.1](LICENSE), and you keep the credit in your rule's `author` field.

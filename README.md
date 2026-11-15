![Mail header inspector](assets/banner.svg)

# Mail header inspector

**Separate a header claim from a verified fact.**

`Python 3.11+` · `Standard library` · `Offline` · `Synthetic examples`

Inspect a saved `.eml` file without opening its attachments or making network requests. The output makes an important distinction: an authentication result written in a header is a **claim**, not something this tool has verified.

| Inspect | Report | Trust boundary |
| --- | --- | --- |
| From, Return-Path, Reply-To | Addresses and normalized domains | Differences may be legitimate |
| Authentication-Results | Reported SPF / DKIM / DMARC results | Every claim is marked `trusted: false` |
| Received headers | Stored order and raw values | No routing or reputation verdict |

## What it deliberately leaves to other evidence

This tool does **not** perform DNS queries, evaluate SPF/DMARC policy, or verify DKIM signatures. Authentication-Results can be forged outside a trusted mail-processing boundary. Confirm claims against a gateway you control. A mismatching domain alone is not proof of phishing.

Only headers are reported. Bodies, links, and attachments are not fetched, executed, or included in the report. Input is limited to 2 MiB.

## References

- [RFC 8601 — Authentication-Results and trust boundaries](https://www.rfc-editor.org/rfc/rfc8601)
- [Python email package](https://docs.python.org/3/library/email.html)

## Quick start

```bash
git clone https://github.com/PROxZONE/mail-header-inspector.git
cd mail-header-inspector
python3 inspect_headers.py examples/review-needed.eml --output out/header-report.json
```

## Example artifacts

See [`examples/`](examples/) for the sample inputs and [`sample-output/`](sample-output/) for generated results. Run the command above to reproduce them locally. Example IPs and domains are documentation data, not testing targets.

## Development

Python 3.11 or newer. No third-party packages are required.

```bash
python3 -m unittest discover -s tests -v
```

Use synthetic or appropriately sanitized data when contributing examples. Describe the observed behavior, the expected behavior, and a reproducible command in an issue.

## About this project

A learning project in [Divyansh Yadav’s cybersecurity portfolio](https://ceodivyansh.com). The examples are fictional and are not evidence of a completed client engagement or production deployment.

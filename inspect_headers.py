#!/usr/bin/env python3
"""Summarise a saved email's headers offline; do not authenticate the message."""
from __future__ import annotations

import argparse
from email import policy
from email.parser import BytesParser
from email.utils import getaddresses
import json
from pathlib import Path
import re

MAX_INPUT_BYTES = 2 * 1024 * 1024


def domain(address: str) -> str | None:
    if address.count('@') != 1 or any(char.isspace() for char in address):
        return None
    local, host = address.rsplit('@', 1)
    if not local or not host:
        return None
    try:
        return host.rstrip('.').encode('idna').decode('ascii').lower()
    except UnicodeError:
        return None


def inspect(raw: bytes) -> dict:
    if not raw.strip() or len(raw) > MAX_INPUT_BYTES:
        raise ValueError('input must be nonempty and no larger than 2 MiB')
    message = BytesParser(policy=policy.default).parsebytes(raw, headersonly=True)
    addresses = lambda field: [address for _, address in getaddresses(
        [str(value) for value in message.get_all(field, [])]) if address]
    senders, returns, replies = addresses('From'), addresses('Return-Path'), addresses('Reply-To')
    from_domain = domain(senders[0]) if len(senders) == 1 else None
    observations = []
    if not senders:
        observations.append('No From address was parsed.')
    if len(senders) > 1 or len(message.get_all('From', [])) > 1:
        observations.append('Multiple From addresses or header fields need manual review.')
    for label, values in (('Return-Path', returns), ('Reply-To', replies)):
        if from_domain and values and domain(values[0]) and domain(values[0]) != from_domain:
            observations.append(f'{label} domain differs from the From domain; legitimate services can do this.')
    authentication = []
    for value in message.get_all('Authentication-Results', []):
        header = str(value)
        claims = [{'method': method.lower(), 'reported_result': result.lower()}
                  for method, result in re.findall(r'\b(spf|dkim|dmarc)\s*=\s*([a-z_-]+)', header, re.I)]
        authentication.append({'authserv_id': header.split(';', 1)[0].strip(),
                               'claims': claims, 'raw_header': header, 'trusted': False})
        if any(claim['reported_result'] in ('fail', 'softfail', 'permerror', 'temperror') for claim in claims):
            observations.append('An Authentication-Results header reports a failure/error; corroborate it with a trusted gateway.')
    return {'schema_version': 1, 'from': senders, 'return_path': returns, 'reply_to': replies,
            'from_domain_ascii': from_domain, 'subject': str(message.get('Subject', '')),
            'message_id': str(message.get('Message-ID', '')),
            'received_headers_in_stored_order': [str(value) for value in message.get_all('Received', [])],
            'authentication_results': authentication, 'observations': observations,
            'parser_defects': [type(defect).__name__ for defect in message.defects],
            'limitations': 'Header claims are untrusted input. This tool performs no DNS queries, SPF evaluation, DKIM signature verification or DMARC evaluation. A domain mismatch alone is not proof of phishing.'}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('message', type=Path, help='saved .eml or header text file')
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    try:
        with args.message.open('rb') as stream:
            raw = stream.read(MAX_INPUT_BYTES + 1)
        encoded = json.dumps(inspect(raw), indent=2, ensure_ascii=False) + '\n'
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(encoded, encoding='utf-8')
        print(encoded, end='')
        return 0
    except (OSError, ValueError) as exc:
        parser.exit(2, f'error: {exc}\n')


if __name__ == '__main__':
    raise SystemExit(main())

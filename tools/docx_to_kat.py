#!/usr/bin/env python3
"""
DOCX → KAT text converter for Ascon tests.

Goal:
- Extract text lines from a DOCX (Word) file using only Python stdlib (zipfile + XML parsing).
- Identify KAT-like records consisting of lines "Field = hex".
- Canonicalize field names minimally to match our KAT parser expectations.
- Classify records into output files (hash256, aead, xof) based on present fields.
- Emit text files under tests/vectors/generated/ without overwriting existing ones unless --force.

Notes:
- This best-effort parser assumes the DOCX contains the KAT text as visible plain lines (typical when KATs
  are pasted into the document). Tables are handled by concatenating cell texts row-wise.
- If the document uses images or unusual formatting, extraction may miss content.

Usage:
  python3 tools/docx_to_kat.py Docs/NIST.SP.800-232.docx

Outputs (created if records exist):
  tests/vectors/generated/hash256.txt
  tests/vectors/generated/aead.txt
  tests/vectors/generated/xof.txt

You can also specify explicit output files via flags.
"""
# MIT License
#
# Copyright (c) 2025 Rahim Ali
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

import argparse
import os
import re
import sys
import zipfile
from xml.etree import ElementTree as ET

# Namespaces used in DOCX XML
NS = {
    'w': 'http://schemas.openxmlformats.org/wordprocessingml/2006/main',
}

FIELD_RE = re.compile(r"^\s*([A-Za-z][A-Za-z0-9_ ]*)\s*=\s*([0-9A-Fa-f]*)\s*$")

CANON_MAP = {
    'npub': 'Nonce',
    'nonce': 'Nonce',
    'digest': 'MD',
    'md': 'MD',
    'msg': 'Msg',
    'pt': 'PT',
    'plaintext': 'PT',
    'ct': 'CT',
    'ciphertext': 'CT',
    'ad': 'AD',
    'aad': 'AD',
    'tag': 'Tag',
    'mac': 'Tag',
    'outlen': 'Outlen',
    'outputlen': 'Outlen',
    'out': 'Output',
    'output': 'Output',
    'key': 'Key',
    'count': 'Count',
}


def extract_docx_lines(docx_path: str):
    """Return a list of plain text lines extracted from the DOCX, preserving paragraph order.

    We consider both body paragraphs and tables. Each paragraph becomes one line.
    Each table row's cells are joined with a single space and considered one line.
    """
    lines = []
    with zipfile.ZipFile(docx_path) as z:
        with z.open('word/document.xml') as f:
            tree = ET.parse(f)
    root = tree.getroot()

    # Collect paragraphs and tables in document order
    # The body contains elements like w:p (paragraph), w:tbl (table)
    body = root.find('.//w:body', NS)
    if body is None:
        return lines

    def get_text(el):
        # concatenate all w:t texts inside el
        text_parts = []
        for t in el.findall('.//w:t', NS):
            text_parts.append(t.text or '')
        return ''.join(text_parts)

    for child in list(body):
        tag = child.tag
        if tag.endswith('}p'):
            text = get_text(child).strip()
            if text:
                lines.append(text)
            else:
                # blank paragraph → separator
                lines.append('')
        elif tag.endswith('}tbl'):
            # iterate rows
            for tr in child.findall('.//w:tr', NS):
                cells_text = []
                for tc in tr.findall('.//w:tc', NS):
                    cells_text.append(get_text(tc).strip())
                line = ' '.join(filter(None, cells_text)).strip()
                if line:
                    lines.append(line)
                else:
                    lines.append('')
        else:
            # Unknown element; skip
            pass

    # Normalize: collapse multiple blank lines but keep at least single separators
    norm = []
    prev_blank = False
    for ln in lines:
        if ln.strip() == '':
            if not prev_blank:
                norm.append('')
            prev_blank = True
        else:
            norm.append(ln)
            prev_blank = False
    return norm


def canonicalize_name(name: str) -> str:
    n = name.strip().lower()
    if n in CANON_MAP:
        return CANON_MAP[n]
    # Title-case unknown names by convention (e.g., "Random" stays as-is)
    return name.strip()


def parse_records_from_lines(lines):
    """Yield records as dicts field->hexstring from a list of lines.
    Records are separated by blank lines or by encountering non field lines.
    """
    rec = {}
    for ln in lines + ['']:
        m = FIELD_RE.match(ln)
        if m:
            name, hexval = m.group(1), m.group(2)
            cname = canonicalize_name(name)
            # empty value allowed → hexval == '' (zero length)
            rec[cname] = hexval
        else:
            # non-field or blank → flush current record if not empty
            if rec:
                yield rec
                rec = {}
            # else ignore
    # Done


def classify_record(rec: dict) -> str | None:
    """Return category: 'hash', 'aead', 'xof', or None if unknown."""
    keys = {k.lower() for k in rec.keys()}
    # HASH: needs Msg/PT and MD/Digest
    if (('msg' in keys or 'pt' in keys or 'PT' in rec) and ('md' in keys or 'digest' in keys or 'MD' in rec)):
        return 'hash'
    # AEAD: key + nonce + tag, usually has PT/AD/CT
    if ('key' in keys or 'Key' in rec) and ('nonce' in keys or 'Nonce' in rec) and ('tag' in keys or 'Tag' in rec):
        return 'aead'
    # XOF: Msg/PT + Outlen + Output
    if (('outlen' in keys or 'Outlen' in rec) and ('output' in keys or 'Output' in rec) and ('msg' in keys or 'pt' in keys or 'PT' in rec)):
        return 'xof'
    return None


def write_records(records, out_path):
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    with open(out_path, 'w', encoding='utf-8') as f:
        for rec in records:
            # Emit Count first if present for readability
            order = []
            if 'Count' in rec:
                order.append('Count')
            # Common fields in a friendly order
            for k in ['Key', 'Nonce', 'AD', 'PT', 'CT', 'Tag', 'Msg', 'MD', 'Outlen', 'Output']:
                if k in rec and k not in order:
                    order.append(k)
            # Any remaining fields
            for k in rec.keys():
                if k not in order:
                    order.append(k)
            for k in order:
                f.write(f"{k} = {rec.get(k, '')}\n")
            f.write('\n')


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('docx', help='Path to DOCX file containing KATs')
    ap.add_argument('--out-hash', default='tests/vectors/generated/hash256.txt')
    ap.add_argument('--out-aead', default='tests/vectors/generated/aead.txt')
    ap.add_argument('--out-xof', default='tests/vectors/generated/xof.txt')
    ap.add_argument('--force', action='store_true', help='Overwrite output files if they exist')
    args = ap.parse_args()

    if not os.path.isfile(args.docx):
        print(f"Input not found: {args.docx}", file=sys.stderr)
        return 2

    lines = extract_docx_lines(args.docx)
    if not lines:
        print("No text extracted from DOCX.", file=sys.stderr)
        return 3

    records = list(parse_records_from_lines(lines))
    if not records:
        print("No KAT-like records found in DOCX.", file=sys.stderr)
        return 4

    hash_recs = []
    aead_recs = []
    xof_recs = []
    for rec in records:
        # Remove spaces from hex values and make lowercase for consistency
        clean = {}
        for k, v in rec.items():
            vv = (v or '').replace(' ', '').replace('\u00A0', '').strip()
            clean[k] = vv
        cat = classify_record(clean)
        if cat == 'hash':
            # Normalize field names to those expected by our tests
            # Prefer 'PT' and 'MD' for hash records
            norm = {}
            if 'Msg' in clean and 'PT' not in clean:
                norm['PT'] = clean['Msg']
            elif 'PT' in clean:
                norm['PT'] = clean['PT']
            if 'MD' in clean:
                norm['MD'] = clean['MD']
            elif 'Digest' in clean:
                norm['MD'] = clean['Digest']
            if 'Count' in clean:
                norm['Count'] = clean['Count']
            hash_recs.append(norm)
        elif cat == 'aead':
            aead_recs.append(clean)
        elif cat == 'xof':
            xof_recs.append(clean)
        else:
            # Unknown category; ignore
            pass

    # Safety: do not overwrite unless --force
    def safe_write(recs, path):
        if not recs:
            return False
        if os.path.exists(path) and not args.force:
            print(f"Refusing to overwrite existing {path} (use --force).", file=sys.stderr)
            return False
        write_records(recs, path)
        print(f"Wrote {len(recs)} records to {path}")
        return True

    wrote_any = False
    wrote_any |= safe_write(hash_recs, args.out_hash)
    wrote_any |= safe_write(aead_recs, args.out_aead)
    wrote_any |= safe_write(xof_recs, args.out_xof)

    if not wrote_any:
        print("No files written (either no recognized records or outputs exist).", file=sys.stderr)
        return 5
    return 0


if __name__ == '__main__':
    sys.exit(main())

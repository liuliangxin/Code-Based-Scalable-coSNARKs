#!/usr/bin/env python3
import argparse
import csv
from pathlib import Path


def split_tokens(value):
    return [token.strip() for token in value.split(';;') if token.strip()]


def locate_in_order(text, tokens):
    positions = []
    cursor = 0
    for token in tokens:
        pos = text.find(token, cursor)
        if pos < 0:
            return None
        positions.append(pos)
        cursor = pos + len(token)
    return positions


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--root', type=Path, default=Path('.'))
    ap.add_argument('--map', dest='map_path', type=Path,
                    default=Path('notes/PAPPAS_PROTOCOL_CODE_MAP.csv'))
    args = ap.parse_args()
    root = args.root.resolve()
    map_path = args.map_path if args.map_path.is_absolute() else root / args.map_path

    with map_path.open(newline='', encoding='utf-8-sig') as handle:
        rows = list(csv.DictReader(handle))
    if not rows:
        raise SystemExit('empty protocol-code map')

    checked = 0
    for row in rows:
        source = root / row['file']
        if not source.is_file():
            raise SystemExit(f"missing file for C{row['construction']}: {row['file']}")
        text = source.read_text(errors='strict')
        symbol = row['symbol'].strip()
        if symbol and symbol not in text:
            raise SystemExit(
                f"missing symbol for C{row['construction']} {row['step']}: {symbol} in {row['file']}")
        for token in split_tokens(row.get('required_tokens', '')):
            if token not in text:
                raise SystemExit(
                    f"missing token for C{row['construction']} {row['step']}: {token}")
        ordered = split_tokens(row.get('ordered_tokens', ''))
        if ordered and locate_in_order(text, ordered) is None:
            raise SystemExit(
                f"ordering mismatch for C{row['construction']} {row['step']}: {ordered}")
        checked += 1
        print(
            f"[MAPPING] PASS C{row['construction']} {row['step']} -> "
            f"{row['file']}::{symbol or '-'}")

    print(f'PROTOCOL_CODE_MAPPING: PASS rows={checked}')


if __name__ == '__main__':
    main()

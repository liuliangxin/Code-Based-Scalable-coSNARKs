#!/usr/bin/env python3
import argparse, csv
from collections import Counter
from pathlib import Path


def split_tokens(value):
    return [x.strip() for x in (value or '').split(';;') if x.strip()]


def in_order(text, tokens):
    cursor=0
    for token in tokens:
        pos=text.find(token,cursor)
        if pos<0: return False
        cursor=pos+len(token)
    return True


def main():
    ap=argparse.ArgumentParser()
    ap.add_argument('--root',type=Path,default=Path('.'))
    ap.add_argument('--alignment',type=Path,default=Path('notes/PVIA_PAPER_IMPLEMENTATION_ALIGNMENT.csv'))
    args=ap.parse_args()
    root=args.root.resolve()
    path=args.alignment if args.alignment.is_absolute() else root/args.alignment
    with path.open(newline='',encoding='utf-8-sig') as f:
        rows=list(csv.DictReader(f))
    if not rows: raise SystemExit('empty paper/implementation alignment map')
    counts=Counter()
    for row in rows:
        status=row['status'].strip().upper()
        if status not in {'IMPLEMENTED','PARTIAL','OPEN'}:
            raise SystemExit(f"unknown status {status} for {row['requirement']}")
        counts[status]+=1
        source=root/row['file']
        if not source.is_file():
            raise SystemExit(f"missing source file for {row['requirement']}: {row['file']}")
        text=source.read_text(errors='strict')
        if status in {'IMPLEMENTED','PARTIAL'}:
            for token in split_tokens(row.get('required_tokens')):
                if token not in text:
                    raise SystemExit(f"missing token for {row['requirement']}: {token}")
            ordered=split_tokens(row.get('ordered_tokens'))
            if ordered and not in_order(text,ordered):
                raise SystemExit(f"ordering mismatch for {row['requirement']}: {ordered}")
        print(f"[ALIGNMENT] {status} {row['layer']} :: {row['requirement']}")
    print('PAPER_IMPLEMENTATION_ALIGNMENT: PASS '
          f"implemented={counts['IMPLEMENTED']} partial={counts['PARTIAL']} open={counts['OPEN']}")

if __name__=='__main__': main()

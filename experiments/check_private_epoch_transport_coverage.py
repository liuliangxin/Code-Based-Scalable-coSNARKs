#!/usr/bin/env python3
import argparse,csv
from collections import Counter
from pathlib import Path

def tokens(value):
    return [x.strip() for x in (value or '').split(';;') if x.strip()]

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument('--root',type=Path,default=Path('.'))
    ap.add_argument('--map',dest='map_path',type=Path,
                    default=Path('notes/PVIA_PRIVATE_EPOCH_TRANSPORT_MAP.csv'))
    args=ap.parse_args()
    root=args.root.resolve()
    path=args.map_path if args.map_path.is_absolute() else root/args.map_path
    with path.open(newline='',encoding='utf-8-sig') as f:
        rows=list(csv.DictReader(f))
    if not rows:
        raise SystemExit('empty private-epoch transport map')
    counts=Counter()
    for row in rows:
        status=row['status'].strip().upper()
        if status not in {'IMPLEMENTED','PARTIAL','OUT_OF_SCOPE'}:
            raise SystemExit(f"unknown status {status}: {row['area']}")
        counts[status]+=1
        source=root/row['file']
        if not source.is_file():
            raise SystemExit(f"missing source for {row['area']}: {row['file']}")
        text=source.read_text(errors='strict')
        symbol=row['symbol'].strip()
        if status=='IMPLEMENTED' and symbol and symbol!='active-native-transfer-inventory':
            if symbol not in text:
                raise SystemExit(f"missing symbol for {row['area']}: {symbol}")
        missing=[tok for tok in tokens(row.get('required_tokens')) if tok not in text]
        if missing:
            raise SystemExit(f"missing tokens for {row['area']}: {missing}")
        if status in {'PARTIAL','OUT_OF_SCOPE'} and not row.get('notes','').strip():
            raise SystemExit(f"{status} row needs explicit notes: {row['area']}")
        print(f"[PRIVATE-EPOCH] {status} {row['area']} :: {row['binding_mode']}")
    print(
        'PRIVATE_EPOCH_TRANSPORT_COVERAGE: PASS '
        f"implemented={counts['IMPLEMENTED']} partial={counts['PARTIAL']} "
        f"out_of_scope={counts['OUT_OF_SCOPE']}")

if __name__=='__main__':
    main()

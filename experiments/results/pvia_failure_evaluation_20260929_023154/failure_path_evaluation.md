# Failure-path evaluation

## Failure handling latency

| Path | Mean ms | Median ms | P95 ms | Scope sync ms | Batch check ms | Certificate verify ms | Runtime cert bytes |
|:---|---:|---:|---:|---:|---:|---:|---:|
| Publicly attributable abort | 9.094 | 9.321 | 11.612 | 2.243 | 6.246 | 0.493 | 1584 |
| Replay / unattributable abort | 4.138 | 3.929 | 5.983 | 1.985 | 2.412 | 0.000 | 0 |

## Independent judge

- Mean verification: 0.776 ms.
- P95 verification: 0.860 ms.
- Canonical certificate: 1280 bytes.
- Serialized certificate file: 2750 bytes.
- Correct registry anchor: ACCEPT; wrong anchor: REJECT.

## No-framing / negative tests

| Boundary | Case | Result |
|:---|:---|:---|
| public-transfer | valid certificate | ACCEPT |
| public-transfer | wrong session | REJECT |
| public-transfer | tampered certificate | REJECT |
| public-transfer | tampered proof | REJECT |
| public-transfer | missing live registry after reset | REJECT |
| public-transfer | wrong registry anchor | REJECT |
| private-localization | upstream faulty / downstream honest | UPSTREAM |
| private-localization | frame downstream honest prover | REJECT |
| activation-binding | sealed activation tamper | REJECT |
| scope-binding | detached transport scope | REJECT |
| state-binding | attested state drift | REJECT |

The private causal case binds the downstream operation statement to the faulty upstream predecessor while keeping the downstream local residual zero. Localization identifies the upstream owner and rejects downstream framing.

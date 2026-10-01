# PVIA accountability cost attribution

Headline overhead uses the uninstrumented paper-aligned paired batch. Runtime attribution uses a separate timing-instrumented batch and is diagnostic only. Communication attribution uses sender-side instrumented accounting. These scopes are deliberately kept separate.

| N | Headline E2E overhead | Full comm factor | Timed top-level share | Init-valid ms | Init-valid / timed | Metadata observe ms |
|---:|---:|---:|---:|---:|---:|---:|
| 4 | 17.0% | 3.74x | 19.6% | 353.2 | 66.6% | 63.5 |
| 8 | 20.3% | 7.26x | 36.9% | 497.0 | 75.2% | 133.5 |
| 16 | 46.5% | 14.48x | 72.3% | 1260.6 | 87.5% | 268.7 |

| N | Auth envelope MiB | Raw control MiB | Init-valid control MiB | Init-valid / raw control | Preproc control MiB | Metadata MiB |
|---:|---:|---:|---:|---:|---:|---:|
| 4 | 120.1 | 38.9 | 36.0 | 92.6% | 2.9 | 0.39 |
| 8 | 280.9 | 96.2 | 84.0 | 87.3% | 12.2 | 0.88 |
| 16 | 607.7 | 226.7 | 180.0 | 79.4% | 46.6 | 1.87 |

Interpretation: the initial-validity gate is the dominant directly timed top-level module, especially at higher party counts. The authenticated envelope is the largest aggregate communication component, while initial-validity traffic dominates the scoped control bytes. Transfer metadata is small in bytes but receive-side observe/verify time grows with the party count; these metadata timers are cross-cutting and are not added to the top-level timing share.

The uninstrumented headline batch remains the source for performance claims. The timing-instrumented batch is used only to explain where the overhead arises.

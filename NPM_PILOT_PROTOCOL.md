# npm policy scout v1, frozen before execution, 17 October 2026

Question: can paired install and functional oracles discriminate existing npm
script controls on public package versions, and can approval refresh be measured?
This is a package-integration feasibility scout, NOT the real-project corpus,
an ecosystem prevalence estimate, a timing benchmark or a novelty test.

Five purposively selected cases and version pairs are fixed in npm_pilot.py.
One Linux x64 hosted runner per case, Node 24.21.0, npm 12.2.1.
Each snapshot has one frozen lock shared by all arms. Initial name/version
approvals come only from initial lock hasInstallScript entries. This flag may
miss implicit lifecycle builds; inspect logs, do not interpret missing entries
as a complete capability model. Preserve lock and exact resolved graphs.

Arms: explicit allow-all, deny-all, initial name approval, initial version
approval, current-version refresh approval. Explicit root functional invocation
uses node, independent of root npm lifecycle. Checks verify output, not import.
Each arm starts with fresh node_modules in its own directory. Registry cache is
shared sequentially: elapsed times are diagnostic ONLY, not comparative speed.
Timeout per command 180 seconds. No retries chosen based on favorable outcomes.
Both version allow-all references must succeed before policy attribution.

Additional local tarball sentinel is harmless: install writes a marker; import
writes a separate marker. Initial pinned approval must allow v1 and block v2;
name approval must allow both; deny-all blocks both; allow-all allows both.
Import marker demonstrates that install controls do not stop explicit runtime
code execution. Any sentinel mismatch invalidates policy comparisons.

Report pending entries and version-pin changes as maintenance proxies, not
human review time or malicious-package detection. No public package publishing,
no real malware, no credentials in experiment subprocesses. No Kubernetes/GPU.
Stop after one complete run plus repairs needed for harness correctness.

Go: valid policy controls, functional reference reproducibility, and useful
classification of outcomes. If no breakages occur, publish that result; don't
alter package versions to manufacture a win. Main thesis still needs paired
real downstream project update snapshots and closest-work review.

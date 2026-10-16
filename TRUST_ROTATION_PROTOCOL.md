# Trust-key rotation feasibility scout

Setup repair after failed run 38872383632: concatenated public keys in one
attestor field did not accept both fixtures on this path. Use two explicit
attestor entries with count=1, sourced from oldSlot/retainedSlot ConfigMap fields.
Rotation sets both slots to the retained public key; the policy spec stays fixed.
The failed run stopped before rotation and is excluded from outcome comparisons.

Declared before execution, 16 October 2026. This is a known-behavior replication
and measurement feasibility check, not a novel-cache or vulnerability claim.

Use the already pinned Kyverno 1.19.1 legacy ClusterPolicy stack, TTL120,
one fresh hosted Kind cluster per session. Generate two disposable signing keys
on the hosted runner. Publish distinct synthetic old-key and retained-key OCI
images with signed SLSA-v1-shaped test attestations. These are NOT claims of a
trusted SLSA builder or SLSA level. Private keys are never uploaded as artifacts.
Transparency logging is explicitly disabled for this keyed isolated experiment;
the earlier keyless/GitHub-attestation pilot remains a different trust contract.

Initial trust accepts both keys. Rotation replaces ConfigMap data with retained
key only. Compare no-cache, native-cache/no-trigger, native-cache/explicit policy
RV bump, each with normal versus blocked GHCR. The bump is a scripted intervention
3 seconds after the ConfigMap API response, NOT a deployed event controller.
Each cell gets a preparation policy revision and warms BOTH images with registry
normal. Rotate trust, optionally bump, wait 3 seconds, then probe both images.
Restore network and probe both again. Record all outcomes; assert setup and
evidence validity, not expected cache results. Run normal no-cache cell first
to establish new-trust oracle. Fresh cosign verification against retained key
is a separate oracle check for both attestations on the runner.

Keep actual ConfigMap and policy versions, public-key hashes, timestamps, cache
age, complete API responses, controller identity/restarts, proxy counters, and
controller logs. Bound requests below TTL; if that fails, exclude stale-cache
attribution. Oracle labels: old-key image should deny under new trust; retained
image should allow. Errors are unavailable evidence, NOT correct security denial.
Admission tests use unschedulable Pods; no inference about image pull or rollout
availability. A successful probe does not prove a finite revocation bound.

Six cells x two seed/probe/recovery images = 36 CREATE per session. One-session
scout first, then three fresh sessions only if the oracle and treatments work.
The fixed phase order and single scout do not support performance significance,
p95/p99, production frequency or novelty. Stop or repair if keyed attestation,
ConfigMap substitution, independent oracle, or network controls fail.

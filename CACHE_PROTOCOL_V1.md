# Cache availability experiment, protocol v1

## Replication amendment v1.1 (2026-10-16, after compatibility scout)

Scout run `38853823596`, source `b810376`, completed with 34 requests. Retain it
separately; do not pool its observations with the three replication sessions.
The deployed controller argument was explicitly
`--imageVerifyCacheTTLDuration=30s`. A wrapped HTTP 400 for proxy failure had
`Service Unavailable` in the verifier message; preserve it as infrastructure
failure, distinct from the registry-on tightened-policy condition denial.

Before dispatching the three sessions, make these fixed validity additions:

1. Assert the actual deployed TTL argument and the authorized fixture digest
   at runtime. After the blocked fresh-image probe, add a registry-on fresh
   authorized control and require acceptance. Do not warm it before the outage.
2. Add eight seconds of sham waiting under blocked registry with unchanged
   policy, then probe again before applying the metadata-only update. Confirm
   the later metadata probe still starts before the 30 second TTL expires.
3. After outage/recovery, seed a new policy revision for each cache treatment,
   accept one normal request, then measure ten sequential normal repeated
   digest requests. Keep the seed request separate from repeats. The sample is
   descriptive: ten repeats per configuration/session, three fresh clusters;
   no p95 SLA or crypto-only timing claim. These extra requests occur after the
   outage probes and before separate freshly seeded TTL/metadata phases.
4. Print phase/status diagnostics and add a self-check for the observed wrapped
   HTTP 400 infrastructure message. Hypothesis outcomes remain unasserted.
5. Pin the admission engine to the manifest digest resolved by the scout:
   `reg.kyverno.io/kyverno/kyverno@sha256:b31d8511ae5fd6010e2a01ea72ebae08eb82fa51d91af14a1d9fe989949b4edb`.

The additions strengthen controls and characterize a cost already seen in the
scout. Hypotheses and fixtures are unchanged. Freeze one new source commit for
all three independent sessions with the original seeds and retain all failures.

Declared 2026-10-16 before the first cache workflow is dispatched. This follows
the completed cold-controller pilot and source inspection; it is not a claim
of a new cache mechanism or a previously undiscovered vulnerability.

## Question and fixed scope

For Kyverno 1.19.1 / chart 3.9.1, how does successful-verification caching
change registry dependence, admission latency and policy freshness for a
digest-pinned synthetic image? All operations concern this public synthetic
repository. No application executes: Pods have an unsatisfiable node selector.

The unit of replication is a fresh GitHub-hosted Kind cluster. First run one
compatibility scout; after infrastructure repairs, run three independent
sessions with seeds 20261016, 20261017, 20261018. Retain failed runs. Within a
session, randomize the enabled/disabled cache treatment order. Repetitions of
one digest are repeated requests, not independent applications.

## Treatments and controls

Use the same P3 authorized-main provenance policy, explicitly toggling only
`verifyImages[].useCache`. Global cache TTL is shortened to 30 seconds. Compare:

1. Normal registry, three authorized warm requests.
2. Warm controller, GHCR blocked via a transparent CONNECT proxy which also
   terminates existing GHCR tunnels. No controller restart. Probe warmed digest
   first, then a distinct authorized digest and an unsigned digest.
3. Restore registry and probe recovery.
4. Cache enabled: warm, block, probe immediately and after TTL plus five seconds.
5. Cache enabled: warm, block, tighten provenance ref policy and probe after
   propagation. Preserve policy UID/resourceVersion and controller Pod UID.
6. Cache enabled, before tightening: repeat warm/block and change only a policy
   metadata annotation. Preserve identical spec hashes and changed
   resourceVersion to test availability after a semantically neutral update.

CONNECT delay, if implemented, affects setup only and is not simulated WAN RTT.
TLS remains end-to-end. Block applies to ghcr.io, not all trust infrastructure.
The control proxy is inside the test cluster and is not a production component.

## Hypotheses fixed before execution

- H1: warmed digest admission can succeed during GHCR unavailability with cache
  enabled, while a distinct authorized digest cannot be verified.
- H2: cache disabled and expired cache both require registry access and reject
  or error during that outage.
- H3: policy tightening changes the cache key and prevents use of the prior
  successful verification result.
- H4: a metadata-only policy update also changes resourceVersion and prevents
  use of that cached result, despite an unchanged policy spec.

These expectations come from source inspection. A failed verification caused
by registry unavailability is an availability cost, never successful attack
detection. This experiment does not test key revocation, malicious runner
compromise, remote evidence deletion, or workload runtime behavior.

## Recording and interpretation

Preserve every response/status/body, monotonic request duration, UTC timestamp,
proxy counters before and after requests, policy/controller identity and
controller cgroup snapshots. Timed unit is Kubernetes API CREATE roundtrip,
not pure crypto time. Cleanup and instrumentation are outside timed CREATE.
CPU observations include controller background work; memory is observational.
Report session-level results and ranges, no tail SLA or general industry rate
from these small samples. A proxy block must show denied fresh connections
and stable controller UID; otherwise outage interpretation is invalid.

Setup assertions require normal authorized acceptance and functioning controls.
No assertion requires hypotheses to come true. Changes after scout must be
listed with their reason; three-session results use one frozen source commit.

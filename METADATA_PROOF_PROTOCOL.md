# Focused metadata-causality check

Declared 2026-10-16 before this workflow runs. Earlier cache study source
`aee78d7` found metadata-only updates followed by registry dependence, but its
`kubectl apply` updated two annotations, and the sham probe occurred earlier
than the post-update probe. This check strengthens those controls; earlier
observations remain archived unchanged.

Three independent fresh clusters use the same pinned engine, Kubernetes,
proxy and authorized image as before. Set verification-result TTL to 120 s.
Randomize three arms within each session (seeds 20261021, 20261022, 20261023):

- Wait only: no policy mutation.
- Single-field JSON PATCH: replace the pre-existing `metadata.annotations[cache-proof/nonce]` with a different value.
- Same-value JSON PATCH: replace that annotation with its existing value.

Each arm gets a distinct preparation policy revision and a successful main-image
seed with registry available. Then block GHCR and terminate existing GHCR
tunnels without restarting the controller. At 15 seconds after the seed CREATE
completes, perform the selected intervention. Allow the same three-second
propagation interval in every arm and probe the same digest. Preserve actual
elapsed time; reject TTL attribution if a probe starts at or beyond 120 s.
Restore registry and require normal authorized acceptance for recovery.

The direct PATCH avoids changing kubectl's last-applied annotation. Record full
before/after policy, exact PATCH body/response, actual changed paths, spec hash,
generation, UID/resourceVersion, process/container/image identity, restart count,
proxy state/counters and full admission response. Server bookkeeping fields
(resourceVersion, managedFields, status) are retained but distinguished from
the requested annotation change.

Predictions, not required outcomes: wait-only accepts; changed annotation with
new RV requires registry and errors when blocked; same-value PATCH acceptance
depends on whether Kubernetes actually preserves the RV. An API request alone
must not be assumed to invalidate the cache. Do not assert these predictions in
the driver. Assert only valid setup, normal seed/recovery acceptance, deployed
TTL and well-formed controls. Preserve failures and unexpected outcomes.

This can establish a reproducible mechanism for this pinned configuration.
It cannot prove universal Kyverno behavior, production incident prevalence,
an undocumented security vulnerability, or scientific novelty. Compare against
the implementation's cache-key design and primary literature separately.

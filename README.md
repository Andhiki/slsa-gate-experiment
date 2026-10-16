# Synthetic SLSA admission experiment

This repository contains synthetic container fixtures and CI workflows for an undergraduate software supply-chain verification study. No thesis documents, production code, credentials or real malware are included. A fixture marker distinguishes artifacts; it is not a malicious payload.

The experiment tests artifact authorization and provenance verification. A valid attestation does not establish that program contents are safe or certify a SLSA Build level.

`workflow_dispatch` builds an OCI image and, unless the fixture is `unsigned`, publishes GitHub-generated SLSA provenance. The image repository is derived from this repository's owner and name. All third-party actions are pinned to resolved commit SHAs. Packages may require an explicit public-visibility setting before anonymous admission verification can fetch them.

## Execution

- `build.yml` creates legitimate, unsigned, or invalid-evidence target images. `substitution` and `tampered` targets intentionally skip attestation too.
- `build-other.yml` supplies a different authenticated workflow identity.
- `mutate-evidence.yml` attaches copied or deliberately modified public evidence to synthetic targets and checks independent verification rejects them.
- `admission.yml` creates ephemeral Kind/Kyverno on the hosted runner, exercises actual CREATE requests, and uploads raw evidence for 30 days. No local Docker cluster is needed.
- Optional performance probes use sequential repeated-digest requests. Optional fault injection restarts the controller and redirects GHCR to loopback; it models a cold-controller registry outage, not all network failures or warm-cache offline verification.

These are exploratory compatibility scripts. Pin the preinstalled kubectl to a version compatible with the node image, record full runner hardware, and freeze a larger randomized protocol before treating measurements as confirmatory research. CPU block counters include controller background and DELETE cleanup. Verification signature and transparency checks must remain enabled.

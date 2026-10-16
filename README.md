# Synthetic SLSA admission experiment

This repository contains synthetic container fixtures and CI workflows for an undergraduate software supply-chain verification study. No thesis documents, production code, credentials or real malware are included. A fixture marker distinguishes artifacts; it is not a malicious payload.

The experiment tests artifact authorization and provenance verification. A valid attestation does not establish that program contents are safe or certify a SLSA Build level.

`workflow_dispatch` builds an OCI image and, unless the fixture is `unsigned`, publishes GitHub-generated SLSA provenance. The image repository is derived from this repository's owner and name. All third-party actions are pinned to resolved commit SHAs. Packages may require an explicit public-visibility setting before anonymous admission verification can fetch them.

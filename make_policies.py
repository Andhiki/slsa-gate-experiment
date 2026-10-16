"""Generate inspectable policies. Compatibility remains unproven until applied."""
import argparse
import copy
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent


def policies(repository):
    assert len(repository.split("/")) == 2 and all(x for x in repository.split("/"))
    workflow = f"https://github.com/{repository}/.github/workflows/build.yml"
    p1 = {
        "apiVersion": "kyverno.io/v1", "kind": "ClusterPolicy",
        "metadata": {"name": "slsa-experiment", "annotations": {"pod-policies.kyverno.io/autogen-controllers": "none"}},
        "spec": {"background": False, "validationFailureAction": "Enforce", "failurePolicy": "Fail",
                 "webhookTimeoutSeconds": 30,
                 "rules": [{"name": "verify-provenance", "match": {"any": [{"resources": {
                     "kinds": ["Pod"], "namespaces": ["slsa-experiment"]}}]},
                     "verifyImages": [{"imageReferences": ["*"], "type": "SigstoreBundle",
                                       "required": True, "verifyDigest": True, "mutateDigest": True,
                                       "attestations": [{"type": "https://slsa.dev/provenance/v1", "attestors": [
                                           {"entries": [{"keyless": {"issuer": "https://token.actions.githubusercontent.com",
                                                                      "subject": "*", "rekor": {"url": "https://rekor.sigstore.dev"}}}]}]}]}]}]}}
    p2 = copy.deepcopy(p1)
    p2["spec"]["rules"][0]["verifyImages"][0]["attestations"][0]["attestors"][0]["entries"][0]["keyless"]["subject"] = workflow + "@refs/heads/*"
    p3 = copy.deepcopy(p2)
    p3["spec"]["rules"][0]["verifyImages"][0]["attestations"][0]["conditions"] = [{"all": [
        {"key": "{{ buildDefinition.buildType }}", "operator": "Equals", "value": "https://actions.github.io/buildtypes/workflow/v1"},
        {"key": "{{ buildDefinition.externalParameters.workflow.repository }}", "operator": "Equals", "value": "https://github.com/" + repository},
        {"key": "{{ buildDefinition.externalParameters.workflow.ref }}", "operator": "Equals", "value": "refs/heads/main"}]}]
    return {"P1": p1, "P2": p2, "P3": p3}


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--repository", default="Andhiki/slsa-gate-experiment")
    args = parser.parse_args()
    out = ROOT / "policies"
    out.mkdir(exist_ok=True)
    for name, policy in policies(args.repository).items():
        (out / f"{name}.json").write_text(json.dumps(policy, indent=2) + "\n", encoding="utf-8")
    print("Generated P1/P2/P3 compatibility candidates; validate actual signed claims before freezing.")

"""Run actual Pod CREATE requests. Labels come from cases.json, never engine output."""
import argparse
import datetime as dt
import hashlib
import json
import pathlib
import random
import subprocess
import time
import uuid

ROOT = pathlib.Path(__file__).resolve().parent


def classify(returncode, stderr):
    if returncode == 0:
        return "allow"
    # A denial is evidence of a policy decision only when the engine says so.
    if "denied the request" in stderr:
        if any(x in stderr.lower() for x in ("timeout", "connection refused", "i/o timeout", "context deadline")):
            return "verification_error"
        return "deny_needs_reason_review"
    return "infrastructure_error"


def run(args):
    cases_bytes = pathlib.Path(args.cases).read_bytes()
    cases = json.loads(cases_bytes)
    assert cases and len({c["id"] for c in cases}) == len(cases)
    assert all(c["oracle"] in ("authorized", "unauthorized", "boundary") for c in cases)
    assert all("@sha256:" in c["image"] for c in cases), "Pin each image digest"
    result_dir = ROOT / "results" / args.run_id
    result_dir.mkdir(parents=True, exist_ok=False)
    (result_dir / "cases.json").write_bytes(cases_bytes)
    policy = pathlib.Path(args.policy).read_bytes() if args.policy else b""
    (result_dir / "policy.snapshot").write_bytes(policy)
    meta = vars(args) | {"created_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
                         "cases_sha256": hashlib.sha256(cases_bytes).hexdigest(),
                         "policy_sha256": hashlib.sha256(policy).hexdigest()}
    (result_dir / "metadata.json").write_text(json.dumps(meta, indent=2), encoding="utf-8")
    base = ["kubectl", "--kubeconfig", args.kubeconfig, "--context", "kind-slsa-gate"]
    subprocess.run(base + ["get", "namespace", args.namespace], check=True, capture_output=True)
    rng = random.Random(args.seed)
    with (result_dir / "requests.jsonl").open("w", encoding="utf-8") as log:
        for block in range(args.blocks):
            order = list(cases)
            rng.shuffle(order)
            for case in order:
                name = "gate-" + uuid.uuid4().hex[:16]
                # Unschedulable nodeSelector isolates admission from image pull/runtime.
                # Actual B0 pullability is checked separately, not inferred from CREATE.
                pod = {"apiVersion": "v1", "kind": "Pod", "metadata": {"name": name, "namespace": args.namespace},
                       "spec": {"nodeSelector": {"slsa-experiment.invalid/node": "none"},
                                "automountServiceAccountToken": False,
                                "containers": [{"name": "fixture", "image": case["image"]}]}}
                start_utc = dt.datetime.now(dt.timezone.utc).isoformat()
                started = time.perf_counter_ns()
                try:
                    p = subprocess.run(base + ["create", "-f", "-", "-o", "json", "--request-timeout=45s"],
                                       input=json.dumps(pod), text=True, capture_output=True, timeout=55)
                    elapsed = (time.perf_counter_ns() - started) / 1e6
                    record = {"case_id": case["id"], "oracle": case["oracle"], "image": case["image"],
                              "block": block, "policy": args.mode, "started_utc": start_utc,
                              "client_process_ms": elapsed, "returncode": p.returncode,
                              "outcome": classify(p.returncode, p.stderr), "stdout": p.stdout, "stderr": p.stderr}
                except subprocess.TimeoutExpired:
                    record = {"case_id": case["id"], "oracle": case["oracle"], "block": block,
                              "policy": args.mode, "started_utc": start_utc, "outcome": "client_timeout"}
                log.write(json.dumps(record) + "\n")
                log.flush()
                print(json.dumps({k: record[k] for k in ("case_id", "outcome", "block")}), flush=True)
                if record["outcome"] == "allow":
                    subprocess.run(base + ["delete", "pod", name, "-n", args.namespace, "--wait=false"],
                                   capture_output=True, timeout=30, check=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--cases", required=True)
    parser.add_argument("--kubeconfig", required=True)
    parser.add_argument("--mode", required=True)
    parser.add_argument("--policy")
    parser.add_argument("--namespace", default="slsa-experiment")
    parser.add_argument("--run-id", default=dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ"))
    parser.add_argument("--blocks", type=int, default=3)
    parser.add_argument("--seed", type=int, default=20261016)
    run(parser.parse_args())

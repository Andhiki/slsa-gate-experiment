"""Run a bounded Kyverno image-verification cache/outage experiment.

The driver records observed admission responses and telemetry. It does not turn
the expected cache behavior into pass/fail assertions.
"""
import copy
import datetime as dt
import hashlib
import json
import os
import pathlib
import random
import re
import subprocess
import time
import urllib.parse
import uuid

import http_probe
from make_policies import policies


ROOT = pathlib.Path(__file__).resolve().parent
OUT = ROOT / "results"
K = http_probe.K
REPOSITORY = "ghcr.io/andhiki/slsa-gate-experiment"
MAIN_DIGEST = "sha256:4f7c122798111cc5a4663aaa7a4a264420222be52a1ebdbe053744eccdb14219"
UNSIGNED_DIGEST = "sha256:46a46d77d43f4e95df2312b6b6cf803717cba0e7b9476777fd29e2df0c023494"
POLICY_NAME = "slsa-experiment"
NAMESPACE = "slsa-experiment"
PROXY_DEPLOYMENT = "deployment/fault-proxy"
PROXY_STATS_URL = "http://localhost:3128/stats"
PROXY_CONTROL_URL = "http://localhost:3128/control"
POLICY_API = "/apis/kyverno.io/v1/clusterpolicies/" + POLICY_NAME
CONTROLLER_SELECTOR = "app.kubernetes.io/component=admission-controller"


def utc_now():
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def command(argv, timeout=30, check=True):
    proc = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
    result = {"argv": argv, "returncode": proc.returncode, "stdout": proc.stdout, "stderr": proc.stderr}
    if check and proc.returncode:
        raise RuntimeError(f"command failed ({proc.returncode}): {' '.join(argv)}: {proc.stderr[-1200:]}")
    return result


def parse_json(text):
    try:
        return json.loads(text)
    except (TypeError, json.JSONDecodeError):
        return None


def write_json(path, value):
    pathlib.Path(path).write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def append_jsonl(path, value):
    with pathlib.Path(path).open("a", encoding="utf-8") as stream:
        stream.write(json.dumps(value, sort_keys=True) + "\n")
        stream.flush()


def kubectl_api(method, path, value=None):
    return http_probe.api(method, path, value)


def proxy_exec(code, timeout=15):
    result = command(K + ["exec", "-n", "kyverno", PROXY_DEPLOYMENT, "--", "python", "-c", code], timeout=timeout)
    return result["stdout"].strip()


def proxy_stats():
    code = ("import urllib.request; ") + f"print(urllib.request.urlopen({PROXY_STATS_URL!r}, timeout=5).read().decode())"
    raw = proxy_exec(code)
    value = parse_json(raw)
    if not isinstance(value, dict):
        raise RuntimeError("fault proxy /stats did not return a JSON object")
    return value


def set_proxy(mode, delay_ms=0):
    assert mode in ("normal", "block", "delay")
    payload = {"mode": mode, "delay_ms": delay_ms, "flush": True}
    code = (
        "import json,urllib.request; "
        f"r=urllib.request.Request({PROXY_CONTROL_URL!r},data=json.dumps({payload!r}).encode(),"
        "headers={'Content-Type':'application/json'},method='POST'); "
        "print(urllib.request.urlopen(r,timeout=5).read().decode())"
    )
    raw = proxy_exec(code)
    value = parse_json(raw)
    if not isinstance(value, dict):
        raise RuntimeError("fault proxy /control did not return a JSON object")
    observed = proxy_stats()
    if observed.get("mode") != mode:
        raise RuntimeError(f"fault proxy control mismatch: requested {mode}, observed {observed.get('mode')}")
    return {"requested": payload, "control_response": value, "stats": observed, "at": utc_now()}


def safe_proxy_stats():
    try:
        return {"sampled_at": utc_now(), "sample": proxy_stats()}
    except Exception as exc:
        return {"sampled_at": utc_now(), "error": f"{type(exc).__name__}: {exc}"}


def safe_cgroup_stats():
    try:
        return {"sampled_at": utc_now(), "sample": http_probe.stats()}
    except Exception as exc:
        return {"sampled_at": utc_now(), "error": f"{type(exc).__name__}: {exc}"}


def api_json(method, path):
    code, body = kubectl_api(method, path)
    return code, parse_json(body), body


def controller_pods():
    query = urllib.parse.urlencode({"labelSelector": CONTROLLER_SELECTOR})
    code, body = kubectl_api("GET", "/api/v1/namespaces/kyverno/pods?" + query)
    if code != 200:
        return code, None
    return code, parse_json(body)


def current_controller_uid():
    code, value = controller_pods()
    if code != 200 or not isinstance(value, dict):
        return None
    items = value.get("items", [])
    ready = []
    for pod in items:
        statuses = pod.get("status", {}).get("containerStatuses", [])
        if pod.get("status", {}).get("phase") == "Running" and statuses and statuses[0].get("ready"):
            ready.append(pod)
    chosen = sorted(ready or items, key=lambda item: item.get("metadata", {}).get("name", ""))
    return chosen[0].get("metadata", {}).get("uid") if chosen else None


def save_environment_snapshot(run_id, config_name, phase, note=None):
    started = utc_now()
    policy_code, policy, policy_body = api_json("GET", POLICY_API)
    pod_code, pods = controller_pods()
    snapshot = {
        "run_id": run_id, "config": config_name, "phase": phase, "note": note,
        "captured_at": started,
        "policy": {"http_status": policy_code, "object": policy, "raw": policy_body},
        "controller_pods": {"http_status": pod_code, "object": pods},
        "controller_pod_uids": [p.get("metadata", {}).get("uid") for p in (pods or {}).get("items", [])],
        "proxy": safe_proxy_stats(), "cgroup": safe_cgroup_stats(),
    }
    append_jsonl(OUT / "cache-controller-snapshots.jsonl", snapshot)
    if policy is not None:
        write_json(OUT / f"{run_id}-{config_name}-{phase}-policy-status.json", policy)
    if pods is not None:
        write_json(OUT / f"{run_id}-{config_name}-{phase}-controller-pods.json", pods)
    return snapshot


def policy_for_cache(use_cache, nonce=None, nonexistent_ref=False):
    policy = copy.deepcopy(policies("Andhiki/slsa-gate-experiment")["P3"])
    verify = policy["spec"]["rules"][0]["verifyImages"][0]
    verify["useCache"] = bool(use_cache)
    if nonexistent_ref:
        conditions = verify["attestations"][0]["conditions"][0]["all"]
        ref_condition = next(c for c in conditions if c["key"] == "{{ buildDefinition.externalParameters.workflow.ref }}")
        ref_condition["value"] = "refs/heads/nonexistent"
    if nonce is not None:
        policy.setdefault("metadata", {}).setdefault("annotations", {})["cache-experiment/nonce"] = str(nonce)
    return policy


def apply_policy(policy, run_id, config_name, phase, wait_seconds=8):
    path = OUT / f"{run_id}-{config_name}-{phase}-policy.json"
    write_json(path, policy)
    before = api_json("GET", POLICY_API)
    applied = command(K + ["apply", "-f", str(path)])
    time.sleep(wait_seconds)
    after = api_json("GET", POLICY_API)
    status = {
        "run_id": run_id, "config": config_name, "phase": phase, "recorded_at": utc_now(),
        "apply": applied,
        "before": {"http_status": before[0], "object": before[1], "raw": before[2]},
        "after": {"http_status": after[0], "object": after[1], "raw": after[2]},
        "resourceVersion": (after[1] or {}).get("metadata", {}).get("resourceVersion"),
        "uid": (after[1] or {}).get("metadata", {}).get("uid"),
        "policy_sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        "propagation_wait_seconds": wait_seconds,
    }
    write_json(OUT / f"{run_id}-{config_name}-{phase}-policy-apply-status.json", status)
    append_jsonl(OUT / "cache-policy-status.jsonl", status)
    save_environment_snapshot(run_id, config_name, phase + "-after-apply")
    return status


def outcome_class(http_status, response, transport_error=None):
    if transport_error:
        return "infrastructure_error"
    if http_status == 201:
        return "accepted"
    if http_status is None or http_status == 0 or http_status >= 500:
        return "infrastructure_error"
    body = response if isinstance(response, dict) else {}
    message = str(body.get("message", "")).lower()
    # A webhook call/timeout failure is infrastructure, even if Kubernetes wraps it
    # in an HTTP 400/500 Status response.
    infrastructure_markers = ("failed calling webhook", "context deadline exceeded", "no endpoints available",
                               "service unavailable", "connection refused", "i/o timeout", "timed out")
    if any(marker in message for marker in infrastructure_markers):
        return "infrastructure_error"
    reason = str(body.get("reason", "")).lower()
    details = body.get("details", {}) if isinstance(body.get("details"), dict) else {}
    text = " ".join((message, reason, str(details.get("causes", "")))).lower()
    policy_markers = (POLICY_NAME, "verifyimages", "image verification", "image verify", "attestation", "denied")
    if http_status in (400, 403) and any(marker in text for marker in policy_markers):
        return "admission_denial"
    return "api_error"


def create_pod(row_context, case, phase, timing_anchor_ns=None, timing_anchor_at=None, control_completed_ns=None,
               control_completed_at=None):
    name = "cache-" + uuid.uuid4().hex[:16]
    pod = {
        "apiVersion": "v1", "kind": "Pod",
        "metadata": {"name": name, "namespace": NAMESPACE},
        "spec": {"nodeSelector": {"slsa-experiment.invalid/node": "none"},
                 "automountServiceAccountToken": False,
                 "containers": [{"name": "fixture", "image": case["image"]}]},
    }
    pre_proxy = safe_proxy_stats()
    pre_cgroup = safe_cgroup_stats()
    uid = current_controller_uid()
    request_started_at = utc_now()
    request_started_ns = time.monotonic_ns()
    transport_error = None
    try:
        status, raw_body = kubectl_api("POST", "/api/v1/namespaces/" + NAMESPACE + "/pods", pod)
    except Exception as exc:
        status, raw_body = None, ""
        transport_error = f"{type(exc).__name__}: {exc}"
    request_completed_ns = time.monotonic_ns()
    request_completed_at = utc_now()
    response_value = parse_json(raw_body)
    if response_value is None:
        response_value = {"raw": raw_body}
    post_proxy = safe_proxy_stats()
    post_cgroup = safe_cgroup_stats()
    cleanup = None
    if status == 201:
        try:
            cleanup_status, cleanup_body = kubectl_api(
                "DELETE", "/api/v1/namespaces/" + NAMESPACE + "/pods/" + name,
                {"apiVersion": "v1", "kind": "DeleteOptions", "gracePeriodSeconds": 0},
            )
            cleanup = {"http_status": cleanup_status, "response": parse_json(cleanup_body) or {"raw": cleanup_body}}
        except Exception as exc:
            cleanup = {"error": f"{type(exc).__name__}: {exc}"}
    row = dict(row_context)
    row.update({
        "phase": phase, "case_id": case["case_id"], "oracle": case["oracle"], "image": case["image"],
        "pod_name": name, "started_at": request_started_at, "completed_at": request_completed_at,
        "latency_ms": (request_completed_ns - request_started_ns) / 1e6,
        "http_status": status, "response": response_value,
        "outcome_class": outcome_class(status, response_value, transport_error),
        "transport_error": transport_error, "controller_pod_uid": uid, "controllerUID": uid,
        "proxy_before": pre_proxy, "proxy_after": post_proxy,
        "cgroup_before": pre_cgroup, "cgroup_after": post_cgroup, "cleanup": cleanup,
    })
    if timing_anchor_ns is not None:
        row["last_warm_success_to_probe_ms"] = (request_started_ns - timing_anchor_ns) / 1e6
        row["last_warm_success_at"] = timing_anchor_at
    if control_completed_ns is not None:
        row["proxy_control_to_probe_ms"] = (request_started_ns - control_completed_ns) / 1e6
        row["proxy_control_completed_at"] = control_completed_at
    append_jsonl(OUT / "cache-requests.jsonl", row)
    return row, request_completed_ns


def run_case(ctx, case, phase, anchor_ns=None, anchor_at=None, control_ns=None, control_at=None):
    row, completed_ns = create_pod(ctx, case, phase, anchor_ns, anchor_at, control_ns, control_at)
    append_jsonl(OUT / "cache-events.jsonl", {
        "run_id": ctx["run_id"], "config": ctx["config"], "phase": phase,
        "case_id": case["case_id"], "event": "request_recorded", "at": utc_now(),
        "http_status": row["http_status"], "outcome_class": row["outcome_class"],
    })
    return row, completed_ns


def case_set(fresh_digest):
    cases = [
        {"case_id": "main", "oracle": "authorized", "image": REPOSITORY + "@" + MAIN_DIGEST},
    ]
    if fresh_digest:
        if not fresh_digest.startswith("sha256:"):
            fresh_digest = "sha256:" + fresh_digest
        if not re.fullmatch(r"sha256:[0-9a-f]{64}", fresh_digest):
            raise ValueError("FRESH_DIGEST must be a sha256 digest")
        if fresh_digest != MAIN_DIGEST:
            cases.append({"case_id": "fresh-authorized", "oracle": "authorized", "image": REPOSITORY + "@" + fresh_digest})
    cases.append({"case_id": "unsigned", "oracle": "unauthorized", "image": REPOSITORY + "@" + UNSIGNED_DIGEST})
    return cases


def warm(ctx, main_case, phase, count=1):
    successes = []
    last_success_ns = None
    last_success_at = None
    rows = []
    for _ in range(count):
        row, completed = run_case(ctx, main_case, phase)
        rows.append(row)
        if row["http_status"] == 201:
            successes.append(row)
            last_success_ns = completed
            last_success_at = row["completed_at"]
    return {"rows": rows, "accepted": len(successes), "last_success_ns": last_success_ns,
            "last_success_at": last_success_at}


def record_control(run_id, config_name, phase, mode):
    control_started_at = utc_now()
    control_started_ns = time.monotonic_ns()
    result = set_proxy(mode)
    control_completed_at = utc_now()
    control_completed_ns = time.monotonic_ns()
    result.update({"control_started_at": control_started_at, "control_completed_at": control_completed_at,
                   "control_duration_ms": (control_completed_ns - control_started_ns) / 1e6,
                   "_control_completed_monotonic_ns": control_completed_ns})
    event = {"run_id": run_id, "config": config_name, "phase": phase, "event": "proxy_control",
             "mode": mode, "at": utc_now(), "result": result}
    append_jsonl(OUT / "cache-events.jsonl", event)
    return result


def run_config(run_id, seed, config, cases, ttl_seconds):
    config_name = "cache-enabled" if config else "cache-disabled"
    ctx = {"run_id": run_id, "seed": seed, "config": config_name,
           "cache": {"useCache": config, "controllerTTL_seconds": ttl_seconds}}
    base_policy = policy_for_cache(config)
    policy_result = apply_policy(base_policy, run_id, config_name, "base")
    save_environment_snapshot(run_id, config_name, "base-ready", note="controller UID and policy identity recorded")
    main = cases[0]
    initial_warm = warm(ctx, main, "warm-initial", count=3)
    if initial_warm["accepted"] != 3:
        raise RuntimeError(f"setup invalid: normal-mode main warm requests were not all accepted for {config_name}")
    last_warm_success_ns = initial_warm["last_success_ns"]
    block_control = record_control(run_id, config_name, "outage-immediate", "block")
    for case in cases:
        count = 3 if case["case_id"] == "main" else 1
        for index in range(count):
            phase = "outage-immediate" if index == 0 else f"outage-immediate-{case['case_id']}-{index + 1}"
            run_case(ctx, case, phase, anchor_ns=last_warm_success_ns,
                     anchor_at=initial_warm["last_success_at"],
                     control_ns=block_control["_control_completed_monotonic_ns"],
                     control_at=block_control["control_completed_at"])
    record_control(run_id, config_name, "outage-recovery", "normal")
    recovery = warm(ctx, main, "outage-recovery", count=1)

    if config:
        # A new policy resourceVersion makes this a fresh positive cache entry for TTL timing.
        ttl_policy = policy_for_cache(True, nonce=f"{seed}-ttl")
        apply_policy(ttl_policy, run_id, config_name, "ttl-seed-policy")
        ttl_warm = warm(ctx, main, "ttl-warm", count=1)
        if ttl_warm["accepted"] != 1:
            raise RuntimeError("setup invalid: fresh positive TTL seed was not accepted in normal mode")
        ttl_anchor = ttl_warm["last_success_ns"]
        ttl_control = record_control(run_id, config_name, "ttl-immediate", "block")
        immediate, _ = run_case(ctx, main, "ttl-immediate", anchor_ns=ttl_anchor,
                                anchor_at=ttl_warm["last_success_at"],
                                control_ns=ttl_control["_control_completed_monotonic_ns"],
                                control_at=ttl_control["control_completed_at"])
        time.sleep(ttl_seconds + 5)
        expired, _ = run_case(ctx, main, "ttl-after-expiry", anchor_ns=ttl_anchor,
                              anchor_at=ttl_warm["last_success_at"],
                              control_ns=ttl_control["_control_completed_monotonic_ns"],
                              control_at=ttl_control["control_completed_at"])
        record_control(run_id, config_name, "ttl-recovery", "normal")
        warm(ctx, main, "ttl-recovery", count=1)

        # Seed a fresh policy revision and positive entry before the metadata change.
        metadata_seed_policy = policy_for_cache(True, nonce=f"{seed}-metadata-seed")
        apply_policy(metadata_seed_policy, run_id, config_name, "metadata-seed-policy")
        metadata_warm = warm(ctx, main, "metadata-warm", count=1)
        if metadata_warm["accepted"] != 1:
            raise RuntimeError("setup invalid: metadata phase positive cache seed was not accepted")
        metadata_control = record_control(run_id, config_name, "metadata-immediate", "block")
        meta_immediate, _ = run_case(ctx, main, "metadata-immediate", anchor_ns=metadata_warm["last_success_ns"],
                                     anchor_at=metadata_warm["last_success_at"],
                                     control_ns=metadata_control["_control_completed_monotonic_ns"],
                                     control_at=metadata_control["control_completed_at"])
        policy_before = api_json("GET", POLICY_API)
        metadata_policy = copy.deepcopy(metadata_seed_policy)
        metadata_policy.setdefault("metadata", {}).setdefault("annotations", {})["cache-experiment/nonce"] = f"{seed}-metadata"
        before_spec_hash = hashlib.sha256(json.dumps((policy_before[1] or {}).get("spec"), sort_keys=True).encode()).hexdigest()
        metadata_status = apply_policy(metadata_policy, run_id, config_name, "metadata-only-update")
        after_spec_hash = hashlib.sha256(json.dumps((metadata_status["after"]["object"] or {}).get("spec"), sort_keys=True).encode()).hexdigest()
        metadata_row, _ = run_case(ctx, main, "metadata-after-update", anchor_ns=metadata_warm["last_success_ns"],
                                   anchor_at=metadata_warm["last_success_at"],
                                   control_ns=metadata_control["_control_completed_monotonic_ns"],
                                   control_at=metadata_control["control_completed_at"])
        append_jsonl(OUT / "cache-events.jsonl", {
            "run_id": run_id, "config": config_name, "phase": "metadata-only-update",
            "event": "spec_identity", "before_spec_sha256": before_spec_hash,
            "after_spec_sha256": after_spec_hash, "spec_unchanged": before_spec_hash == after_spec_hash,
            "before_resourceVersion": (policy_before[1] or {}).get("metadata", {}).get("resourceVersion"),
            "after_resourceVersion": metadata_status.get("resourceVersion"),
        })
        record_control(run_id, config_name, "metadata-recovery", "normal")
        warm(ctx, main, "metadata-recovery", count=1)

    # Tightening while the proxy is blocked separates cache invalidation behavior
    # from the actual policy oracle under restored registry access.
    tightening_seed_policy = policy_for_cache(config, nonce=f"{seed}-tightening-seed")
    apply_policy(tightening_seed_policy, run_id, config_name, "tightening-seed-policy")
    tight_seed = warm(ctx, main, "tightening-warm", count=1)
    if tight_seed["accepted"] != 1:
        raise RuntimeError("setup invalid: tightening phase positive cache seed was not accepted")
    tightening_control = record_control(run_id, config_name, "policy-invalidation", "block")
    tight_policy = policy_for_cache(config, nonce=f"{seed}-tightened", nonexistent_ref=True)
    apply_policy(tight_policy, run_id, config_name, "tightened-policy")
    blocked_tight = run_case(ctx, main, "policy-invalidation", anchor_ns=tight_seed["last_success_ns"],
                             anchor_at=tight_seed["last_success_at"],
                             control_ns=tightening_control["_control_completed_monotonic_ns"],
                             control_at=tightening_control["control_completed_at"])
    record_control(run_id, config_name, "tightened-policy-normal", "normal")
    normal_tight = run_case(ctx, main, "tightened-policy-normal")[0]
    restored_policy = policy_for_cache(config, nonce=f"{seed}-restored")
    apply_policy(restored_policy, run_id, config_name, "restored-policy")
    restored = run_case(ctx, main, "restored-policy-normal")[0]
    record_control(run_id, config_name, "finish", "normal")
    save_environment_snapshot(run_id, config_name, "finish")
    return {
        "config": config_name, "cache_enabled": config,
        "base_policy_uid": policy_result.get("uid"), "base_policy_resourceVersion": policy_result.get("resourceVersion"),
        "warm_initial_accepted": initial_warm["accepted"], "recovery": recovery,
        "ttl_immediate": immediate if config else None, "ttl_after_expiry": expired if config else None,
        "metadata_immediate": meta_immediate if config else None, "metadata_after_update": metadata_row if config else None,
        "policy_invalidation": blocked_tight, "tightened_policy_normal": normal_tight,
        "restored_policy_normal": restored,
    }


def summarize(run_id, seed, ttl_seconds, configs, cases, results):
    rows = []
    request_path = OUT / "cache-requests.jsonl"
    if request_path.exists():
        for line in request_path.read_text(encoding="utf-8").splitlines():
            row = json.loads(line)
            if row.get("run_id") == run_id:
                rows.append(row)
    grouped = {}
    for row in rows:
        key = (row.get("config", "unknown"), row.get("phase", "unknown"), row.get("case_id", "unknown"))
        record = grouped.setdefault("|".join(key), {"requests": 0, "http_statuses": {}, "outcome_classes": {}})
        record["requests"] += 1
        status_key = str(row.get("http_status"))
        outcome = row.get("outcome_class", "unknown")
        record["http_statuses"][status_key] = record["http_statuses"].get(status_key, 0) + 1
        record["outcome_classes"][outcome] = record["outcome_classes"].get(outcome, 0) + 1
    summary = {
        "run_id": run_id, "seed": seed, "created_at": utc_now(), "cache_ttl_seconds": ttl_seconds,
        "configs_order": ["cache-enabled" if c else "cache-disabled" for c in configs],
        "cases": cases, "observed_results": results, "request_count": len(rows),
        "grouped_observations": grouped,
        "outcome_class_definitions": {
            "accepted": "Kubernetes API returned 201 for CREATE",
            "admission_denial": "4xx response text identifies policy/image verification/attestation/denial",
            "infrastructure_error": "transport, 5xx, or explicit webhook/network availability failure",
            "api_error": "other non-201 response; inspect full response JSON",
        },
        "limitations": ["Sequential synthetic Pod CREATEs; API roundtrip includes webhook and API-server overhead.",
                        "A proxy outage is synthetic and scoped to this experiment.",
                        "Observed outcomes are recorded without asserting hypothesized cache behavior."],
    }
    write_json(OUT / "cache-summary.json", summary)
    return summary


def self_check():
    """Check immutable fixture wiring and the policy/outcome labels used by the run."""
    fixtures = json.loads((ROOT / "cache-fixtures.json").read_text(encoding="utf-8"))
    assert fixtures["repository"] == "Andhiki/slsa-gate-experiment"
    assert fixtures["image_repository"] == REPOSITORY
    assert fixtures["main"]["digest"] == MAIN_DIGEST
    assert fixtures["main"]["oracle"] == "authorized"
    assert fixtures["unsigned"]["digest"] == UNSIGNED_DIGEST
    assert fixtures["unsigned"]["oracle"] == "unauthorized"
    assert re.fullmatch(r"sha256:[0-9a-f]{64}", fixtures["fresh_authorized"]["digest"])
    configured_fresh = os.environ.get("FRESH_DIGEST", "").strip()
    if configured_fresh:
        configured_fresh = configured_fresh if configured_fresh.startswith("sha256:") else "sha256:" + configured_fresh
        assert configured_fresh == fixtures["fresh_authorized"]["digest"]

    enabled = policy_for_cache(True)
    disabled = policy_for_cache(False)
    assert enabled["spec"]["rules"][0]["verifyImages"][0]["useCache"] is True
    assert disabled["spec"]["rules"][0]["verifyImages"][0]["useCache"] is False
    original_conditions = enabled["spec"]["rules"][0]["verifyImages"][0]["attestations"][0]["conditions"][0]["all"]
    ref_key = "{{ buildDefinition.externalParameters.workflow.ref }}"
    assert next(c["value"] for c in original_conditions if c["key"] == ref_key) == "refs/heads/main"
    tightened = policy_for_cache(True, nonexistent_ref=True)
    tightened_conditions = tightened["spec"]["rules"][0]["verifyImages"][0]["attestations"][0]["conditions"][0]["all"]
    assert next(c["value"] for c in tightened_conditions if c["key"] == ref_key) == "refs/heads/nonexistent"
    metadata_a = policy_for_cache(True, nonce="self-check-a")
    metadata_b = policy_for_cache(True, nonce="self-check-b")
    assert metadata_a["spec"] == metadata_b["spec"]
    assert metadata_a["metadata"]["annotations"] != metadata_b["metadata"]["annotations"]

    assert outcome_class(201, {"kind": "Pod"}) == "accepted"
    assert outcome_class(503, {"reason": "ServiceUnavailable"}) == "infrastructure_error"
    denial = {"kind": "Status", "reason": "Forbidden",
              "message": "admission webhook denied the Pod because slsa-experiment image attestation verification failed"}
    assert outcome_class(403, denial) == "admission_denial"
    fresh_cases = case_set(fixtures["fresh_authorized"]["digest"])
    assert [case["case_id"] for case in fresh_cases] == ["main", "fresh-authorized", "unsigned"]
    return {"ok": True, "fixture_digests_match": True, "policy_checks": True, "outcome_checks": True}


def main():
    OUT.mkdir(exist_ok=True)
    seed = int(os.environ.get("SEED", "20261016"))
    ttl_seconds = int(os.environ.get("CACHE_TTL_SECONDS", "30"))
    if ttl_seconds <= 0 or ttl_seconds > 240:
        raise ValueError("CACHE_TTL_SECONDS must be between 1 and 240")
    fresh_digest = os.environ.get("FRESH_DIGEST", "").strip()
    cases = case_set(fresh_digest)
    configs = [False, True]
    random.Random(seed).shuffle(configs)
    run_id = os.environ.get("RUN_ID", f"cache-{seed}-{dt.datetime.now().strftime('%Y%m%dT%H%M%S%fZ')}")
    (OUT / "cache-requests.jsonl").touch(exist_ok=True)
    (OUT / "cache-policy-status.jsonl").touch(exist_ok=True)
    (OUT / "cache-controller-snapshots.jsonl").touch(exist_ok=True)
    (OUT / "cache-events.jsonl").touch(exist_ok=True)
    write_json(OUT / f"{run_id}-manifest.json", {
        "run_id": run_id, "seed": seed, "created_at": utc_now(), "ttl_seconds": ttl_seconds,
        "repository": REPOSITORY, "main_digest": MAIN_DIGEST, "fresh_digest": fresh_digest or None,
        "unsigned_digest": UNSIGNED_DIGEST, "configs_order": ["cache-enabled" if c else "cache-disabled" for c in configs],
        "proxy_deployment": "kyverno/fault-proxy", "proxy_url": "localhost:3128",
        "controller_cache_ttl_assumption": "controller imageVerifyCacheTTLDuration configured by the workflow",
        "cases": cases,
    })
    proxy_process = None
    try:
        proxy_process = http_probe.start_proxy()
        initial = set_proxy("normal")
        if initial["stats"].get("mode") != "normal":
            raise RuntimeError("setup invalid: fault proxy did not enter normal mode")
        results = []
        for enabled in configs:
            results.append(run_config(run_id, seed, enabled, cases, ttl_seconds))
        summary = summarize(run_id, seed, ttl_seconds, configs, cases, results)
        print(json.dumps({"run_id": run_id, "request_count": summary["request_count"],
                          "configs_order": summary["configs_order"]}, indent=2))
    finally:
        try:
            set_proxy("normal")
        except Exception as exc:
            append_jsonl(OUT / "cache-events.jsonl", {"run_id": run_id, "event": "cleanup_proxy_error",
                                                        "at": utc_now(), "error": f"{type(exc).__name__}: {exc}"})
        if proxy_process is not None and proxy_process.poll() is None:
            proxy_process.terminate()
            try:
                proxy_process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proxy_process.kill()
                proxy_process.wait(timeout=5)


if __name__ == "__main__":
    main()

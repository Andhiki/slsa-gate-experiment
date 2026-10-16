"""Matched-age proof for Kyverno cache behavior after metadata-only policy patches."""
import copy
import datetime as dt
import hashlib
import json
import os
import pathlib
import random
import time
import urllib.error
import urllib.request

import cache_trial


ROOT = cache_trial.ROOT
OUT = cache_trial.OUT
POLICY_API = cache_trial.POLICY_API
TARGET_AGE_SECONDS = 15
PROPAGATION_SECONDS = 3
ARM_NAMES = {"A": "wait-only", "B": "annotation-change", "C": "annotation-noop"}
PATCH_ANNOTATION = "cache-proof/nonce"
PATCH_PATH = "/metadata/annotations/" + PATCH_ANNOTATION.replace("~", "~0").replace("/", "~1")


def pointer_escape(token):
    return str(token).replace("~", "~0").replace("/", "~1")


def _diff_paths(before, after, path=""):
    if isinstance(before, dict) and isinstance(after, dict):
        keys = set(before) | set(after)
        for key in sorted(keys):
            child = f"{path}/{pointer_escape(key)}"
            if child in ("/status", "/metadata/resourceVersion", "/metadata/managedFields"):
                continue
            if key not in before or key not in after:
                yield child
            else:
                yield from _diff_paths(before[key], after[key], child)
    elif isinstance(before, list) and isinstance(after, list):
        for index in range(max(len(before), len(after))):
            child = f"{path}/{index}"
            if index >= len(before) or index >= len(after):
                yield child
            else:
                yield from _diff_paths(before[index], after[index], child)
    elif before != after:
        yield path or "/"


def changed_paths(before, after):
    return sorted(set(_diff_paths(before, after)))


def arm_policy(seed, arm):
    if arm not in ARM_NAMES:
        raise ValueError(f"unknown proof arm: {arm}")
    policy = cache_trial.policy_for_cache(True, nonce=f"metadata-proof-{seed}-{arm}-prep")
    annotations = policy.setdefault("metadata", {}).setdefault("annotations", {})
    annotations[PATCH_ANNOTATION] = "seed"
    return policy


def self_check():
    assert pointer_escape("cache-proof/nonce") == "cache-proof~1nonce"
    assert pointer_escape("a~b/c") == "a~0b~1c"
    before = {"metadata": {"resourceVersion": "1", "managedFields": [{"x": 1}],
                           "annotations": {"cache-proof/nonce": "seed"}},
              "spec": {"verifyImages": [{"useCache": True, "required": True}]},
              "status": {"state": "old"}}
    after = copy.deepcopy(before)
    after["metadata"]["resourceVersion"] = "2"
    after["metadata"]["managedFields"] = [{"x": 2}]
    after["status"] = {"state": "new"}
    after["metadata"]["annotations"]["cache-proof/nonce"] = "changed"
    assert changed_paths(before, after) == ["/metadata/annotations/cache-proof~1nonce"]
    after["spec"]["verifyImages"][0]["required"] = False
    assert "/spec/verifyImages/0/required" in changed_paths(before, after)
    generated = [arm_policy(7, arm) for arm in ("A", "B", "C")]
    assert all(p["spec"]["rules"][0]["verifyImages"][0]["useCache"] is True for p in generated)
    assert all(p["metadata"]["annotations"][PATCH_ANNOTATION] == "seed" for p in generated)
    assert len({p["metadata"]["annotations"]["cache-experiment/nonce"] for p in generated}) == 3
    assert PATCH_PATH == "/metadata/annotations/cache-proof~1nonce"
    return {"ok": True, "json_pointer": True, "diff_paths": True, "arm_generation": True}


def emit(event, **fields):
    record = {"at": cache_trial.utc_now(), "event": event, **fields}
    print(json.dumps(record, sort_keys=True), flush=True)
    cache_trial.append_jsonl(OUT / "metadata-proof-events.jsonl", record)


def full_policy_snapshot(phase):
    status, obj, raw = cache_trial.api_json("GET", POLICY_API)
    snapshot = {"phase": phase, "captured_at": cache_trial.utc_now(),
                "http_status": status, "object": obj, "raw": raw}
    return snapshot


def controller_snapshot(phase):
    status, obj = cache_trial.controller_pods()
    items = (obj or {}).get("items", [])
    containers = []
    for pod in items:
        for container in pod.get("status", {}).get("containerStatuses", []):
            containers.append({
                "pod_name": pod.get("metadata", {}).get("name"),
                "pod_uid": pod.get("metadata", {}).get("uid"),
                "container_name": container.get("name"),
                "container_id": container.get("containerID"),
                "image": container.get("image"),
                "image_id": container.get("imageID"),
                "restart_count": container.get("restartCount"),
                "ready": container.get("ready"),
            })
    return {"phase": phase, "captured_at": cache_trial.utc_now(), "http_status": status,
            "controller_pods": obj, "container_statuses": containers}


def json_patch_policy(operations):
    request = urllib.request.Request(
        http_probe_base() + POLICY_API,
        data=json.dumps(operations, separators=(",", ":")).encode("utf-8"),
        method="PATCH",
        headers={"Content-Type": "application/json-patch+json", "Accept": "application/json"},
    )
    started_at = cache_trial.utc_now()
    started_ns = time.monotonic_ns()
    try:
        with urllib.request.urlopen(request, timeout=40) as response:
            status = response.status
            raw = response.read().decode("utf-8", errors="replace")
            headers = dict(response.headers.items())
    except urllib.error.HTTPError as exc:
        status = exc.code
        raw = exc.read().decode("utf-8", errors="replace")
        headers = dict(exc.headers.items()) if exc.headers else {}
        transport_error = None
    except Exception as exc:
        status = None
        raw = ""
        headers = {}
        transport_error = f"{type(exc).__name__}: {exc}"
    else:
        transport_error = None
    finished_ns = time.monotonic_ns()
    result = {"started_at": started_at, "completed_at": cache_trial.utc_now(),
              "latency_ms": (finished_ns - started_ns) / 1e6,
              "request_content_type": "application/json-patch+json",
              "operations": operations, "http_status": status,
              "response": cache_trial.parse_json(raw) or {"raw": raw}, "response_raw": raw,
              "response_headers": headers, "transport_error": transport_error}
    return result


def http_probe_base():
    return cache_trial.http_probe.BASE


def utc_elapsed_ms(earlier, later):
    first = dt.datetime.fromisoformat(earlier.replace("Z", "+00:00"))
    second = dt.datetime.fromisoformat(later.replace("Z", "+00:00"))
    return (second - first).total_seconds() * 1000


def run_arm(run_id, seed, arm, main_case, ttl_observation):
    arm_name = ARM_NAMES[arm]
    config_name = "metadata-proof-" + arm
    ctx = {"run_id": run_id, "seed": seed, "config": "cache-enabled",
           "cache": {"useCache": True, "controllerTTL_seconds": 120},
           "proof_arm": arm, "proof_arm_name": arm_name}
    emit("arm_start", run_id=run_id, seed=seed, arm=arm, arm_name=arm_name)
    cache_trial.record_control(run_id, config_name, f"{arm}-normal-before", "normal")
    policy = arm_policy(seed, arm)
    apply_record = cache_trial.apply_policy(policy, run_id, config_name, f"{arm}-prepare", wait_seconds=8)
    prepared = full_policy_snapshot("prepared-after-8s")
    prepared_obj = prepared.get("object") or {}
    annotations = prepared_obj.get("metadata", {}).get("annotations", {})
    if annotations.get(PATCH_ANNOTATION) != "seed":
        raise RuntimeError(f"setup invalid: {arm} policy lacks pre-existing {PATCH_ANNOTATION}=seed")
    if prepared_obj.get("spec", {}).get("rules", [{}])[0].get("verifyImages", [{}])[0].get("useCache") is not True:
        raise RuntimeError(f"setup invalid: {arm} policy is not cache-enabled")
    policy_generation = prepared_obj.get("metadata", {}).get("generation")
    seed_row, seed_completed_ns = cache_trial.run_case(ctx, main_case, f"{arm}-seed")
    seed_time = seed_row["completed_at"]
    if seed_row["http_status"] != 201:
        raise RuntimeError(f"setup invalid: {arm} authorized cache seed was not accepted")
    emit("seed_accepted", run_id=run_id, arm=arm, seed_completed_at=seed_time,
         policy_uid=prepared_obj.get("metadata", {}).get("uid"),
         policy_resourceVersion=prepared_obj.get("metadata", {}).get("resourceVersion"))
    policy_after_seed = full_policy_snapshot("after-seed")
    controller_before = controller_snapshot("before-block")
    block_control = cache_trial.record_control(run_id, config_name, f"{arm}-block", "block")

    elapsed = (time.monotonic_ns() - seed_completed_ns) / 1e9
    remaining = TARGET_AGE_SECONDS - elapsed
    if remaining > 0:
        time.sleep(remaining)
    action_started_ns = time.monotonic_ns()
    action_started_at = cache_trial.utc_now()
    action_age_ms = (action_started_ns - seed_completed_ns) / 1e6
    policy_before_patch = full_policy_snapshot("before-arm-action")
    before_obj = policy_before_patch.get("object") or {}
    patch_receipt = None
    if arm == "A":
        action = {"kind": "wait-only", "mutation": False}
    else:
        value = f"seed-{seed}-changed" if arm == "B" else "seed"
        operations = [{"op": "replace", "path": PATCH_PATH, "value": value}]
        patch_receipt = json_patch_policy(operations)
        cache_trial.append_jsonl(OUT / "metadata-proof-patches.jsonl", {
            "run_id": run_id, "seed": seed, "arm": arm, "arm_name": arm_name,
            "patch_receipt": patch_receipt,
        })
        emit("patch_receipt", run_id=run_id, seed=seed, arm=arm,
             http_status=patch_receipt["http_status"], operations=operations)
        if patch_receipt["http_status"] != 200:
            raise RuntimeError(f"setup invalid: {arm} JSON Patch returned HTTP {patch_receipt['http_status']}")
        action = {"kind": "json-patch", "mutation": True, "value": value,
                  "receipt": patch_receipt}

    propagation_started_at = cache_trial.utc_now()
    time.sleep(PROPAGATION_SECONDS)
    propagation_completed_at = cache_trial.utc_now()
    policy_after_propagation = full_policy_snapshot("after-propagation-wait")
    after_obj = policy_after_propagation.get("object") or {}
    expected_annotation = "seed" if arm in ("A", "C") else f"seed-{seed}-changed"
    actual_annotation = after_obj.get("metadata", {}).get("annotations", {}).get(PATCH_ANNOTATION)
    if actual_annotation != expected_annotation:
        mismatch = {"run_id": run_id, "seed": seed, "arm": arm,
                    "expected_annotation": expected_annotation, "actual_annotation": actual_annotation,
                    "policy_after_propagation": policy_after_propagation, "patch_receipt": patch_receipt}
        cache_trial.append_jsonl(OUT / "metadata-proof-patches.jsonl", mismatch)
        emit("annotation_setup_mismatch", **mismatch)
        raise RuntimeError(f"setup invalid: {arm} resulting annotation did not match the patch value")
    paths = changed_paths(before_obj, after_obj)
    spec_hash_before = hashlib.sha256(json.dumps(before_obj.get("spec"), sort_keys=True).encode()).hexdigest()
    spec_hash_after = hashlib.sha256(json.dumps(after_obj.get("spec"), sort_keys=True).encode()).hexdigest()
    controller_after_mutation = controller_snapshot("after-propagation")
    probe_row, _ = cache_trial.run_case(ctx, main_case, f"{arm}-probe",
                                        anchor_ns=seed_completed_ns, anchor_at=seed_time,
                                        control_ns=block_control["_control_completed_monotonic_ns"],
                                        control_at=block_control["control_completed_at"])
    probe_age = utc_elapsed_ms(seed_time, probe_row["started_at"])
    cache_trial.record_control(run_id, config_name, f"{arm}-normal-recovery", "normal")
    recovery_row, _ = cache_trial.run_case(ctx, main_case, f"{arm}-recovery")
    if recovery_row["http_status"] != 201:
        raise RuntimeError(f"setup invalid: {arm} authorized main recovery was not accepted")
    controller_after = controller_snapshot("after-recovery")

    result = {
        "arm": arm, "arm_name": arm_name, "run_id": run_id, "seed": seed,
        "cache": ctx["cache"], "ttl_observation": ttl_observation,
        "policy_apply_status": apply_record,
        "policy_prepared": prepared, "policy_after_seed": policy_after_seed,
        "policy_before_action": policy_before_patch,
        "policy_after_propagation": policy_after_propagation,
        "policy_uid": before_obj.get("metadata", {}).get("uid"),
        "resourceVersion_before": before_obj.get("metadata", {}).get("resourceVersion"),
        "resourceVersion_after": after_obj.get("metadata", {}).get("resourceVersion"),
        "generation_before": before_obj.get("metadata", {}).get("generation"),
        "generation_after": after_obj.get("metadata", {}).get("generation"),
        "prepared_generation": policy_generation,
        "spec_sha256_before": spec_hash_before, "spec_sha256_after": spec_hash_after,
        "spec_unchanged": spec_hash_before == spec_hash_after,
        "changed_paths_excluding_resourceVersion_managedFields_status": paths,
        "patch_receipt": patch_receipt, "action": action,
        "action_started_at": action_started_at, "seed_to_action_ms": action_age_ms,
        "target_seed_age_seconds": TARGET_AGE_SECONDS,
        "propagation_wait_seconds": PROPAGATION_SECONDS,
        "propagation_started_at": propagation_started_at,
        "propagation_completed_at": propagation_completed_at,
        "seed_completed_at": seed_time, "probe_started_at": probe_row["started_at"],
        "probe_age_ms": probe_age,
        "seed_request": seed_row, "probe_request": probe_row,
        "recovery_request": recovery_row,
        "controller_before": controller_before,
        "controller_after_mutation": controller_after_mutation,
        "controller_after_recovery": controller_after,
    }
    return result


def main():
    OUT.mkdir(exist_ok=True)
    check = self_check()
    emit("self_check", **check)
    seed = int(os.environ.get("SEED", "20261016"))
    ttl_seconds = int(os.environ.get("CACHE_TTL_SECONDS", "120"))
    if ttl_seconds != 120:
        raise ValueError("metadata proof requires CACHE_TTL_SECONDS=120")
    run_id = os.environ.get("RUN_ID", f"metadata-proof-{seed}-{dt.datetime.now().strftime('%Y%m%dT%H%M%S%fZ')}")
    digest = cache_trial.MAIN_DIGEST
    main_case = {"case_id": "main", "oracle": "authorized", "image": cache_trial.REPOSITORY + "@" + digest}
    order = ["A", "B", "C"]
    random.Random(seed).shuffle(order)
    proxy_process = None
    completed = []
    output = {"run_id": run_id, "seed": seed, "created_at": cache_trial.utc_now(),
              "repository": cache_trial.REPOSITORY, "image": main_case["image"],
              "ttl_seconds_required": 120, "target_seed_age_seconds": TARGET_AGE_SECONDS,
              "propagation_wait_seconds": PROPAGATION_SECONDS,
              "arm_order": order, "arm_definitions": ARM_NAMES,
              "self_check": check, "arms_completed": completed,
              "hypotheses_are_observations_only": True}
    proof_path = OUT / "metadata-proof.json"
    cache_trial.write_json(proof_path, output)
    try:
        proxy_process = cache_trial.http_probe.start_proxy()
        cache_trial.record_control(run_id, "metadata-proof", "initial-normal", "normal")
        ttl_observation = cache_trial.inspect_controller_cache_ttl(ttl_seconds)
        cache_trial.write_json(OUT / "metadata-proof-controller-deployment.json", ttl_observation)
        cache_trial.CONTROLLER_DEPLOYMENT_OBSERVATION = {
            key: value for key, value in ttl_observation.items() if key not in ("object", "raw")
        }
        output["controller_ttl_check"] = cache_trial.CONTROLLER_DEPLOYMENT_OBSERVATION
        output["controller_deployment_file"] = "metadata-proof-controller-deployment.json"
        cache_trial.write_json(proof_path, output)
        for arm in order:
            result = run_arm(run_id, seed, arm, main_case, cache_trial.CONTROLLER_DEPLOYMENT_OBSERVATION)
            completed.append(result)
            output["arms_completed"] = completed
            output["updated_at"] = cache_trial.utc_now()
            cache_trial.write_json(proof_path, output)
            emit("arm_complete", run_id=run_id, seed=seed, arm=arm,
                 probe_status=result["probe_request"]["http_status"],
                 probe_outcome=result["probe_request"]["outcome_class"],
                 seed_to_probe_ms=result["probe_age_ms"],
                 resourceVersion_before=result["resourceVersion_before"],
                 resourceVersion_after=result["resourceVersion_after"],
                 changed_paths=result["changed_paths_excluding_resourceVersion_managedFields_status"])
        output["completed_at"] = cache_trial.utc_now()
        cache_trial.write_json(proof_path, output)
    finally:
        try:
            cache_trial.record_control(run_id, "metadata-proof", "cleanup-normal", "normal")
        except Exception as exc:
            emit("cleanup_proxy_error", run_id=run_id, error=f"{type(exc).__name__}: {exc}")
        if proxy_process is not None and proxy_process.poll() is None:
            proxy_process.terminate()
            try:
                proxy_process.wait(timeout=5)
            except Exception:
                proxy_process.kill()
                proxy_process.wait(timeout=5)


if __name__ == "__main__":
    main()

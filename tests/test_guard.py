from concurrent.futures import ThreadPoolExecutor

import pytest

from nonce.guard import (
    ciphertext_overlap,
    counter_next,
    detect_reuse,
    gcm_nonce,
    nonce_batch,
    nonce_for,
    record_use,
    validate_policy,
)


def test_counter_never_wraps_to_negative():
    # 缺陷 1：有符号计数器会在回绕后变负并重复旧值。
    state = {"last": -1, "width": 4}
    issued = [counter_next(state) for _ in range(16)]
    assert issued == list(range(16))
    with pytest.raises(OverflowError):
        counter_next(state)
    assert state["last"] == 15


def test_nonce_derivation_binds_key_identifier():
    # 缺陷 2：派生必须使用密钥标识，不能只使用计数器。
    first = nonce_for("key-a", 5)
    second = nonce_for("key-b", 5)
    assert len(first) == 12
    assert first != second
    assert nonce_for("key-a", 5) == first


def test_gcm_nonce_keeps_counter_segment():
    # 缺陷 3：固定段不能占满整块，计数段必须留下。
    with pytest.raises(ValueError):
        gcm_nonce("key-a", 1, b"F" * 12)
    nonce = gcm_nonce("key-a", 1, b"F" * 4)
    assert len(nonce) == 12
    assert nonce[:4] == b"F" * 4
    assert nonce[4:] == (1).to_bytes(8, "big")


def test_record_use_is_scoped_to_key():
    # 缺陷 4：登记键必须同时包含 key_id 与 nonce。
    seen = {"uses": [], "limit": 8, "evicted": 0}
    first = record_use(seen, "key-a", b"\x01" * 12)
    second = record_use(seen, "key-b", b"\x01" * 12)
    assert first["duplicate"] is False
    assert second["duplicate"] is False
    assert second["position"] is None


def test_detect_reuse_finds_common_prefix():
    # 缺陷 5：近似重用必须比较公共前缀，而不能只比较完整相等。
    records = [
        {"key_id": "key-a", "nonce": b"\x10\x20\x30\x40"},
        {"key_id": "key-a", "nonce": b"\x10\x20\x99\x99"},
    ]
    findings = detect_reuse(records)
    assert len(findings) == 1
    finding = findings[0]
    assert finding["key_id"] == "key-a"
    assert finding["kind"] == "near"
    assert finding["position"] == 1
    assert finding["first_position"] == 0
    assert finding["common_prefix"] == 2


def test_ciphertext_overlap_stops_at_first_difference():
    # 缺陷 6：公共前缀不是异或求和，位置不同的相同字节不能计入。
    assert ciphertext_overlap(b"\x01\x02\x03\x04", b"\x01\x02\xff\x04") == 2
    assert ciphertext_overlap(b"\x01\x02", b"\xff\x02") == 0
    assert ciphertext_overlap(b"\xaa\xbb", b"\xaa\xbb\xcc") == 2


def test_policy_rejects_short_counter_width():
    # 缺陷 7：策略校验必须拒绝 32 位计数器。
    policy = {
        "counter_bits": 32,
        "nonce_bytes": 12,
        "fixed_bytes": 4,
        "reuse_detection": True,
    }
    assert validate_policy(policy) == ["counter_width_too_small"]


def test_policy_rejects_oversized_fixed_segment():
    # 缺陷 8：过长的固定段会挤压计数段并降低熵。
    policy = {
        "counter_bits": 64,
        "nonce_bytes": 12,
        "fixed_bytes": 8,
        "reuse_detection": True,
    }
    assert validate_policy(policy) == ["fixed_segment_too_long"]


def test_batch_counters_are_independent_per_key():
    # 缺陷 9：第二个密钥不能从第一个密钥的计数继续。
    policy = {
        "batch_size": 2,
        "counter_bits": 64,
        "nonce_bytes": 12,
        "fixed_bytes": 4,
        "reuse_detection": True,
    }
    batch = nonce_batch(["key-a", "key-b"], policy)
    solo = nonce_batch(["key-b"], policy)
    assert batch["key-b"] == solo["key-b"]
    assert batch["key-a"][0] != batch["key-b"][0]


def test_record_use_bounds_memory():
    # 缺陷 10：旧记录必须清理，内存不能无界增长。
    seen = {"uses": [], "limit": 2, "evicted": 0}
    for value in (b"\x01", b"\x02", b"\x03"):
        record_use(seen, "key-a", value * 12)
    assert len(seen["uses"]) == 2
    assert seen["evicted"] == 1


def test_same_key_consecutive_nonces_differ():
    policy = {
        "batch_size": 2,
        "counter_bits": 64,
        "nonce_bytes": 12,
        "fixed_bytes": 4,
        "reuse_detection": True,
    }
    nonces = nonce_batch(["key-a"], policy)["key-a"]
    assert len(nonces) == 2
    assert nonces[0] != nonces[1]


def test_different_keys_same_counter_differ():
    policy = {
        "batch_size": 1,
        "counter_bits": 64,
        "nonce_bytes": 12,
        "fixed_bytes": 4,
        "reuse_detection": True,
    }
    batch = nonce_batch(["key-a", "key-b"], policy)
    assert batch["key-a"][0] != batch["key-b"][0]


def test_reuse_detection_reports_exact_position():
    records = [
        {"key_id": "key-a", "nonce": b"\x05" * 12},
        {"key_id": "key-b", "nonce": b"\x07" * 12},
        {"key_id": "key-a", "nonce": b"\x05" * 12},
    ]
    findings = detect_reuse(records)
    assert len(findings) == 1
    finding = findings[0]
    assert finding["kind"] == "exact"
    assert finding["position"] == 2
    assert finding["first_position"] == 0
    assert finding["common_prefix"] == 12


def test_batch_nonce_length_matches_policy():
    policy = {
        "batch_size": 3,
        "counter_bits": 64,
        "nonce_bytes": 12,
        "fixed_bytes": 4,
        "reuse_detection": True,
    }
    nonces = nonce_batch(["key-a"], policy)["key-a"]
    assert len(nonces) == 3
    assert all(len(nonce) == policy["nonce_bytes"] for nonce in nonces)


def test_independent_batches_match_individual_runs():
    policy = {
        "batch_size": 2,
        "counter_bits": 64,
        "nonce_bytes": 12,
        "fixed_bytes": 4,
        "reuse_detection": True,
    }
    # 两批并发分配时，每个密钥的序号仍必须从 0 开始。
    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [
            pool.submit(nonce_batch, ["key-a", "key-b"], policy)
            for _ in range(2)
        ]
        first, second = [future.result() for future in futures]
    assert first == second
    assert first["key-a"] == nonce_batch(["key-a"], policy)["key-a"]

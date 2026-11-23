"""Nonce guard 的安全契约与实现。

本文件恰好包含 8 个公开函数，实现 README 中描述的 10 个缺陷的修复。
实现只允许使用标准库 hashlib、hmac、collections。
"""
import hashlib
import hmac


def _key_bytes(key_id: str | bytes) -> bytes:
    """把密钥标识规范化为非空 bytes。"""
    if isinstance(key_id, str):
        raw = key_id.encode("utf-8")
    elif isinstance(key_id, (bytes, bytearray, memoryview)):
        raw = bytes(key_id)
    else:
        raise ValueError("key_id must be str or bytes")
    if not raw:
        raise ValueError("key_id must not be empty")
    return raw


def _positive_int(value, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise ValueError(f"{name} must be a positive integer")
    return value


def counter_next(state: dict) -> int:
    """推进无符号计数器并返回新签发的值。

    state 是可变字典，至少包含：
    - width：计数器宽度，单位为 bit，必须是正整数。
    - last：上一次签发的值，初始化时使用 -1。

    契约：
    - 计数器按无符号整数解释，合法范围是 0 到 2 ** width - 1。
    - 返回 last + 1，并把新值写回 state["last"]。
    - 到达上界后必须在回绕前抛 OverflowError，且 state 保持不变；
      不得回绕成负数，也不得回到 0 造成旧值重复。
    - 重复检测为严格相等，容差 0：同一个 state 不得返回已经签发过的值。
    """
    width = _positive_int(state["width"], "width")
    last = state.get("last", -1)
    if not isinstance(last, int) or isinstance(last, bool):
        raise ValueError("last must be an integer")

    upper = (1 << width) - 1
    next_value = last + 1
    # 有符号回绕与回到 0 都会重复旧值；到达上界即失败，不回绕。
    if next_value > upper:
        raise OverflowError("counter exhausted")

    state["last"] = next_value
    return next_value


def nonce_for(key_id: str | bytes, counter: int) -> bytes:
    """由密钥标识与计数器派生 12 字节随机数。

    契约：
    - key_id 必须是非空 str 或 bytes，并且必须参与派生，不能只作为元数据。
    - counter 是 64 位无符号整数，计数器宽度为 64 bit，范围 0 到
      2 ** 64 - 1。
    - 输出固定为 12 字节：HMAC-SHA256(key=key_id, msg=b"nonce:" + counter 的
      8 字节大端表示) 的前 12 字节。不使用随机源，也不读取模块状态。
    - 相同 key_id 与 counter 必须得到相同结果；同一 counter 下不同 key_id
      必须得到不同结果。
    - 重复检测按完整字节严格比较，容差 0。
    """
    key = _key_bytes(key_id)
    if not isinstance(counter, int) or isinstance(counter, bool):
        raise ValueError("counter must be an integer")
    if counter < 0 or counter > (1 << 64) - 1:
        raise ValueError("counter out of 64-bit unsigned range")

    message = b"nonce:" + counter.to_bytes(8, "big")
    return hmac.new(key, message, hashlib.sha256).digest()[:12]


def gcm_nonce(key_id: str | bytes, counter: int, fixed: bytes) -> bytes:
    """把固定段与计数段拼接成 12 字节的 GCM 随机数。

    契约：
    - fixed 是 bytes 类对象，长度必须严格小于 12，至少给计数段留下 1 字节。
      长度为 12 时计数段被挤掉，必须抛 ValueError。
    - 计数段使用 12 - len(fixed) 字节的大端无符号编码；计数器宽度就是
      12 - len(fixed) 字节。counter 必须能放进这个宽度，否则抛
      OverflowError；任何情况下都不得截断计数段。
    - 返回 bytes(fixed) + 计数段，长度恰好 12 字节。
    - key_id 必须非空，用于确认归属；它不能替代固定段，也不改变拼接布局。
    - 重复检测按完整 12 字节严格比较，容差 0。
    """
    _key_bytes(key_id)
    if not isinstance(fixed, (bytes, bytearray, memoryview)):
        raise ValueError("fixed must be bytes-like")
    fixed = bytes(fixed)

    counter_bytes = 12 - len(fixed)
    if counter_bytes < 1:
        # 固定段占满整块会把计数段挤掉。
        raise ValueError("fixed segment leaves no room for counter")

    if not isinstance(counter, int) or isinstance(counter, bool):
        raise ValueError("counter must be an integer")
    # 任何情况下都不得截断计数段。
    if counter < 0 or counter >= (1 << (8 * counter_bytes)):
        raise OverflowError("counter does not fit in counter segment")

    return fixed + counter.to_bytes(counter_bytes, "big")


def record_use(seen: dict, key_id: str | bytes, nonce: bytes) -> dict:
    """登记一次密钥与随机数的使用，并在保留窗口内报告精确重复。

    seen 是可变字典，至少包含：
    - uses：已登记记录列表，每条记录含 key_id 与 nonce。
    - limit：正整数，保留窗口的最大记录条数。
    - evicted：可选累计清理计数，缺失时按 0 处理。

    契约：
    - 比较键必须是 key_id 与 nonce 的组合，不能只比较 nonce；同一段随机数
      在不同密钥下不是重复。
    - 重复检测只做完整相等比较，容差 0；本函数不做近似前缀检测。
    - 返回字典包含 duplicate、position、count、evicted：
      duplicate 表示当前调用是否重复；position 是保留列表中首次命中的
      零基下标，未命中为 None；count 是包含本次调用在内的出现次数；
      evicted 是累计清理条数。
    - 先查询再追加；追加后若超过 limit，从最旧记录开始清理，保证内存有界。
    - 本函数不签发计数器；计数器宽度由 counter_next 的 state 负责。
    """
    if not isinstance(seen, dict):
        raise ValueError("seen must be a dict")
    uses = seen.get("uses")
    if not isinstance(uses, list):
        raise ValueError("seen['uses'] must be a list")
    limit = _positive_int(seen.get("limit"), "limit")
    evicted = seen.get("evicted", 0)
    if isinstance(evicted, bool) or not isinstance(evicted, int) or evicted < 0:
        raise ValueError("evicted must be a non-negative integer")

    key = _key_bytes(key_id)
    if not isinstance(nonce, (bytes, bytearray, memoryview)):
        raise ValueError("nonce must be bytes-like")
    nonce = bytes(nonce)

    # 比较键是 key_id 与 nonce 的组合；只比较 nonce 会把跨密钥误判为重复。
    position = None
    count = 1
    for index, record in enumerate(uses):
        try:
            same_key = _key_bytes(record["key_id"]) == key
        except (KeyError, ValueError):
            same_key = False
        same_nonce = bytes(record["nonce"]) == nonce if "nonce" in record else False
        if same_key and same_nonce:
            if position is None:
                position = index
            count += 1

    uses.append({"key_id": key_id, "nonce": nonce})

    # 追加后从最旧记录开始清理，内存有界。
    while len(uses) > limit:
        uses.pop(0)
        evicted += 1
    seen["evicted"] = evicted

    return {
        "duplicate": position is not None,
        "position": position,
        "count": count,
        "evicted": evicted,
    }


def detect_reuse(records: list[dict]) -> list[dict]:
    """批量检测完整重复与近似重复的随机数使用。

    records 按发生顺序排列，每条记录含 key_id 与 nonce。

    契约：
    - 计数器宽度由签发层决定，本函数只消费已生成的 nonce 字节。
    - 重复检测只在相同 key_id 的记录之间比较。
    - 完整相等报告 exact。
    - 不相等但最长公共前缀至少 1 字节时报告 near；容差 0 表示只认从
      第 0 字节开始的严格公共前缀，不允许跳过任何差异字节。
    - 每个当前记录最多报告一条结果：优先 exact；否则取最长 near，
      并列时取最早位置。
    - 返回列表元素包含 key_id、position、first_position、kind、
      common_prefix；kind 只能是 exact 或 near。
    - 记录为空或没有重用返回空列表。
    """
    if not isinstance(records, list):
        raise ValueError("records must be a list")

    normalized = []
    for record in records:
        if not isinstance(record, dict):
            raise ValueError("each record must be a dict")
        normalized.append(
            (_key_bytes(record["key_id"]), bytes(record["nonce"]))
        )

    findings = []
    for position, (key, nonce) in enumerate(normalized):
        exact_first = None
        best_near_first = None
        best_near_prefix = 0

        for first in range(position):
            prior_key, prior_nonce = normalized[first]
            if prior_key != key:
                continue

            if prior_nonce == nonce:
                # 完整相等优先；取最早命中位置。
                if exact_first is None:
                    exact_first = first
                continue

            prefix = _common_prefix_len(nonce, prior_nonce)
            if prefix < 1:
                continue
            # 最长 near 优先，并列时取最早位置。
            if prefix > best_near_prefix:
                best_near_prefix = prefix
                best_near_first = first

        if exact_first is not None:
            findings.append(
                {
                    "key_id": records[position]["key_id"],
                    "position": position,
                    "first_position": exact_first,
                    "kind": "exact",
                    "common_prefix": len(nonce),
                }
            )
        elif best_near_first is not None:
            findings.append(
                {
                    "key_id": records[position]["key_id"],
                    "position": position,
                    "first_position": best_near_first,
                    "kind": "near",
                    "common_prefix": best_near_prefix,
                }
            )

    return findings


def _common_prefix_len(a: bytes, b: bytes) -> int:
    """从第 0 字节起逐字节比较，返回严格公共前缀长度。"""
    limit = min(len(a), len(b))
    for index in range(limit):
        if a[index] != b[index]:
            return index
    return limit


def ciphertext_overlap(a: bytes, b: bytes) -> int:
    """返回两段密文的严格公共前缀长度。

    契约：
    - 本函数不接触计数器；计数器宽度由签发层保证。它服务于重复检测中的
      重复流嗅探，不签发随机数。
    - 从第 0 字节开始逐字节比较，遇到第一个不同字节或较短输入结束即停止。
    - 一方是另一方前缀时返回较短长度。
    - 容差 0：不能使用异或求和等聚合技巧，位置不同的相同字节不计入重叠。
    """
    if not isinstance(a, (bytes, bytearray, memoryview)):
        raise ValueError("a must be bytes-like")
    if not isinstance(b, (bytes, bytearray, memoryview)):
        raise ValueError("b must be bytes-like")
    return _common_prefix_len(bytes(a), bytes(b))


def validate_policy(policy: dict) -> list[str]:
    """返回策略问题代码列表，按固定顺序排列。

    policy 至少包含 counter_bits、nonce_bytes、fixed_bytes、reuse_detection。

    契约：
    - 计数器宽度 counter_bits 小于 64 时报告 counter_width_too_small；
      32 位计数器在高速分配下会很快回绕。
    - 计数段需要 ceil(counter_bits / 8) 字节。fixed_bytes 大于
      nonce_bytes 减去该字节数时，报告 fixed_segment_too_long；固定段过长
      会挤压计数段并降低随机数熵。
    - reuse_detection 不为 True 时报告 reuse_detection_disabled。
    - 结果顺序固定为计数器宽度、固定段长度、重复检测开关；无问题时返回
      空列表。问题判定容差 0，不忽略任何一项。
    - 非字典或缺少字段时抛 ValueError。
    """
    if not isinstance(policy, dict):
        raise ValueError("policy must be a dict")

    required = ("counter_bits", "nonce_bytes", "fixed_bytes", "reuse_detection")
    for field in required:
        if field not in policy:
            raise ValueError(f"policy missing field: {field}")

    counter_bits = policy["counter_bits"]
    nonce_bytes = policy["nonce_bytes"]
    fixed_bytes = policy["fixed_bytes"]
    for name, value in (
        ("counter_bits", counter_bits),
        ("nonce_bytes", nonce_bytes),
        ("fixed_bytes", fixed_bytes),
    ):
        if isinstance(value, bool) or not isinstance(value, int):
            raise ValueError(f"{name} must be an integer")
    if counter_bits <= 0 or nonce_bytes <= 0 or fixed_bytes < 0:
        raise ValueError("policy numeric fields out of range")

    problems = []

    # 顺序固定：计数器宽度、固定段长度、重复检测开关。
    if counter_bits < 64:
        problems.append("counter_width_too_small")

    counter_bytes = -(-counter_bits // 8)  # ceil(counter_bits / 8)
    if fixed_bytes > nonce_bytes - counter_bytes:
        problems.append("fixed_segment_too_long")

    if policy["reuse_detection"] is not True:
        problems.append("reuse_detection_disabled")

    return problems


def nonce_batch(keys: list[str | bytes], policy: dict) -> dict:
    """按策略为多个密钥独立批量分配随机数。

    keys 是密钥标识序列，不能含空值或重复项。policy 至少包含
    batch_size、counter_bits、nonce_bytes、fixed_bytes、reuse_detection。

    契约：
    - 先用 validate_policy 校验；若返回问题，抛 ValueError，异常信息含问题码。
    - nonce_bytes 必须是 12，与 GCM 随机数长度一致，否则抛 ValueError。
    - 每个 key_id 分配 batch_size 个随机数，长度均为 nonce_bytes。
    - 每个密钥使用自己的计数器状态，从 0 开始；第二个密钥不得接着第一个
      密钥的计数继续。计数器宽度由 policy 的 counter_bits 指定。
    - 固定段由 key_id 经 HMAC-SHA256 派生并截断到 fixed_bytes，再调用
      gcm_nonce 拼接计数段。
    - 函数不保留模块级状态；相同参数重复调用必须得到相同结果。
    - 重复检测按完整字节严格比较，容差 0。
    """
    if not isinstance(policy, dict):
        raise ValueError("policy must be a dict")
    if "batch_size" not in policy:
        raise ValueError("policy missing field: batch_size")
    batch_size = _positive_int(policy["batch_size"], "batch_size")

    # 先校验策略；错误码直接进入异常信息。
    problems = validate_policy(policy)
    if problems:
        raise ValueError("invalid policy: " + ", ".join(problems))

    if policy["nonce_bytes"] != 12:
        raise ValueError("nonce_bytes must be 12 for GCM nonces")

    if not isinstance(keys, (list, tuple)):
        raise ValueError("keys must be a sequence")
    normalized_keys = [_key_bytes(key_id) for key_id in keys]
    if len(set(normalized_keys)) != len(normalized_keys):
        raise ValueError("keys must not contain duplicates")

    fixed_bytes = policy["fixed_bytes"]
    counter_bits = policy["counter_bits"]

    result = {}
    for key_id, key in zip(keys, normalized_keys):
        # 每个密钥拥有独立的计数器状态，始终从 0 开始。
        state = {"last": -1, "width": counter_bits}
        fixed = hmac.new(
            key, b"fixed:" + key, hashlib.sha256
        ).digest()[:fixed_bytes]

        nonces = []
        for _ in range(batch_size):
            counter = counter_next(state)
            nonces.append(gcm_nonce(key_id, counter, fixed))
        result[key_id] = nonces

    return result

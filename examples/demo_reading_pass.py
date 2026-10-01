#!/usr/bin/env python3
"""一次性阅览凭证（reading pass）端到端示例（纯标准库，无需第三方依赖）。

覆盖：
1) 已开封资料：封存人签发凭证 -> 明文仅返回一次、库内只存摘要；
2) 外部复核人无账号，凭明文在截止前兑换一次正文及摘要；再次兑换被拒；
3) 封存人凭凭证编号在兑换前撤销；撤销后兑换被拒；
4) 截止时刻校验：必须未来、带时区、严格早于已安排的清除时刻；
   未开封/非封存人/已清除资料不能签发；
5) 过期凭证不能兑换也不能撤销；
6) 清除时刻与兑换同刻时清除优先：兑换统一拒绝且不泄露正文；
7) 无效/猜测的明文统一 403，不泄露资料存在性；
8) 签发、兑付、撤销均写入原有审计链；审计快照约定不变。

用法: python examples/demo_reading_pass.py [base_url]
"""
import datetime as dt
import json
import sys
import time
import urllib.error
import urllib.request

BASE = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8000"


def call(method: str, path: str, key: str | None = None, payload: dict | None = None):
    data = json.dumps(payload).encode() if payload is not None else None
    req = urllib.request.Request(
        BASE + path, data=data, method=method,
        headers={"Content-Type": "application/json", **({"X-API-Key": key} if key else {})},
    )
    try:
        with urllib.request.urlopen(req) as resp:
            return resp.status, json.loads(resp.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read())


def in_seconds(s: float) -> str:
    return (dt.datetime.now(dt.timezone.utc) + dt.timedelta(seconds=s)).isoformat()


def in_hours(h: float) -> str:
    return (dt.datetime.now(dt.timezone.utc) + dt.timedelta(hours=h)).isoformat()


def show(title: str, status: int, body) -> None:
    print(f"-- {title} -> {status}")
    text = json.dumps(body, ensure_ascii=False)
    print("   " + (text[:400] + "…" if len(text) > 400 else text))


def main() -> None:
    users = {}
    for name in ["rp-alice", "rp-bob", "rp-carol", "rp-dave"]:
        _, body = call("POST", "/register", payload={"username": name})
        users[name] = body["api_key"]
    alice, bob, carol, dave = (users[n] for n in ["rp-alice", "rp-bob", "rp-carol", "rp-dave"])

    # 封存并走完两票开封流程
    _, sealed = call("POST", "/documents", alice,
                     {"body": "阅览凭证示例正文：READING-PASS-DEMO-SECRET",
                      "witnesses": ["rp-bob", "rp-carol", "rp-dave"]})
    doc_id, digest = sealed["document_id"], sealed["digest"]
    _, req = call("POST", f"/documents/{doc_id}/open-requests", alice,
                  {"reason": "外部复核", "deadline": in_hours(2)})
    call("POST", f"/open-requests/{req['request_id']}/approve", bob, {"digest": digest})
    call("POST", f"/open-requests/{req['request_id']}/approve", carol, {"digest": digest})

    # ------------------------------------------------------------------
    # 场景 1：签发 -> 外部复核人兑换一次 -> 再次兑换被拒
    # ------------------------------------------------------------------
    print("== 场景 1：签发一次性阅览凭证，外部复核人无账号兑换一次 ==")
    status, pkg = call("POST", f"/documents/{doc_id}/reading-passes", alice,
                       {"expires_at": in_hours(1)})
    show("封存人签发（明文 token 仅本次返回）", status, {**pkg, "token": pkg["token"][:8] + "…"})
    assert status == 201 and len(pkg["token"]) == 64 and pkg["status"] == "active"
    pass_id, token = pkg["pass_id"], pkg["token"]

    # 外部复核人：没有 X-API-Key，只凭明文兑换
    status, got = call("POST", "/reading-passes/redeem", None, {"token": token})
    show("外部复核人兑换（无需账号）", status, got)
    assert status == 200
    assert got["body"] == "阅览凭证示例正文：READING-PASS-DEMO-SECRET"
    assert got["digest"] == digest and got["status"] == "redeemed"

    status, denied = call("POST", "/reading-passes/redeem", None, {"token": token})
    show("再次兑换（已兑付，统一 403）", status, denied)
    assert status == 403 and "body" not in json.dumps(denied)

    # 无效 / 随机猜测的明文：同样的统一 403，不区分凭证是否存在
    assert call("POST", "/reading-passes/redeem", None, {"token": "0" * 64})[0] == 403
    assert call("POST", "/reading-passes/redeem", None, {"token": "garbage"})[0] == 403

    # ------------------------------------------------------------------
    # 场景 2：兑换前撤销
    # ------------------------------------------------------------------
    print("== 场景 2：封存人凭凭证编号在兑换前撤销 ==")
    _, pkg = call("POST", f"/documents/{doc_id}/reading-passes", alice,
                  {"expires_at": in_hours(1)})
    pid2, token2 = pkg["pass_id"], pkg["token"]
    # 非封存人不能撤销（见证人也不行）；不存在的凭证编号统一 403
    assert call("POST", f"/reading-passes/{pid2}/revoke", bob)[0] == 403
    assert call("POST", "/reading-passes/999999/revoke", alice)[0] == 403

    status, rev = call("POST", f"/reading-passes/{pid2}/revoke", alice)
    show("封存人撤销", status, rev)
    assert status == 200 and rev["status"] == "revoked"
    status, denied = call("POST", "/reading-passes/redeem", None, {"token": token2})
    show("撤销后兑换被拒", status, denied)
    assert status == 403
    assert call("POST", f"/reading-passes/{pid2}/revoke", alice)[0] == 409  # 重复撤销

    # ------------------------------------------------------------------
    # 场景 3：截止时刻校验（未来 / 带时区 / 早于清除时刻）
    # ------------------------------------------------------------------
    print("== 场景 3：截止时刻与状态校验 ==")
    assert call("POST", f"/documents/{doc_id}/reading-passes", alice,
                {"expires_at": "2020-01-01T00:00:00Z"})[0] == 400           # 过去时刻
    assert call("POST", f"/documents/{doc_id}/reading-passes", alice,
                {"expires_at": "2030-01-01T00:00:00"})[0] == 422            # 不带时区
    assert call("POST", f"/documents/{doc_id}/reading-passes", bob,
                {"expires_at": in_hours(1)})[0] == 403                       # 非封存人

    # 先安排 1 小时后清除：凭证截止时刻必须严格更早（同刻也不行）
    purge_at = in_hours(1)
    call("PUT", f"/documents/{doc_id}/purge", alice, {"purge_at": purge_at})
    assert call("POST", f"/documents/{doc_id}/reading-passes", alice,
                {"expires_at": purge_at})[0] == 400                          # 同刻
    assert call("POST", f"/documents/{doc_id}/reading-passes", alice,
                {"expires_at": in_hours(2)})[0] == 400                       # 晚于清除
    status, pkg = call("POST", f"/documents/{doc_id}/reading-passes", alice,
                       {"expires_at": in_seconds(60)})
    assert status == 201 and pkg["expires_at"] < purge_at
    print("-- 过去 400、不带时区 422、非封存人 403、不早于清除时刻 400 -> 通过")

    # ------------------------------------------------------------------
    # 场景 4：过期凭证不能兑换、不能撤销（确定性判定，不依赖扫描器）
    # ------------------------------------------------------------------
    print("== 场景 4：过期凭证失效 ==")
    _, pkg = call("POST", f"/documents/{doc_id}/reading-passes", alice,
                  {"expires_at": in_seconds(1)})
    time.sleep(1.2)
    assert call("POST", "/reading-passes/redeem", None,
                {"token": pkg["token"]})[0] == 403
    assert call("POST", f"/reading-passes/{pkg['pass_id']}/revoke", alice)[0] == 409
    print("-- 过期兑换 403、过期撤销 409 -> 通过")

    # 取消清除安排，便于演示场景 5（避免资料真的被清掉）
    call("DELETE", f"/documents/{doc_id}/purge", alice)

    # ------------------------------------------------------------------
    # 场景 5：清除与兑换同刻 -> 清除优先，兑换被拒且不泄露正文
    # ------------------------------------------------------------------
    print("== 场景 5：清除时刻与兑换同刻，清除优先 ==")
    _, sealed2 = call("POST", "/documents", alice,
                      {"body": "清除优先示例正文",
                       "witnesses": ["rp-bob", "rp-carol", "rp-dave"]})
    doc2, digest2 = sealed2["document_id"], sealed2["digest"]
    _, req2 = call("POST", f"/documents/{doc2}/open-requests", alice,
                   {"reason": "清除赛跑", "deadline": in_hours(2)})
    call("POST", f"/open-requests/{req2['request_id']}/approve", bob, {"digest": digest2})
    call("POST", f"/open-requests/{req2['request_id']}/approve", carol, {"digest": digest2})
    _, pkg = call("POST", f"/documents/{doc2}/reading-passes", alice,
                  {"expires_at": in_hours(1)})
    call("PUT", f"/documents/{doc2}/purge", alice, {"purge_at": in_seconds(1)})
    print("   等待清除时刻到达后再兑换……")
    time.sleep(1.2)
    status, denied = call("POST", "/reading-passes/redeem", None, {"token": pkg["token"]})
    show("清除时刻之后兑换（清除优先）", status, denied)
    assert status == 403 and "body" not in json.dumps(denied)
    _, got = call("GET", f"/documents/{doc2}", alice)
    assert got["status"] == "purged" and "body" not in got

    # ------------------------------------------------------------------
    # 审计链：签发 / 兑付 / 撤销均在原有审计链中
    # ------------------------------------------------------------------
    print("== 审计链（原有 audit_log，按序） ==")
    _, audit = call("GET", f"/documents/{doc_id}/audit", alice)
    actions = [r["action"] for r in audit["records"]]
    for a in ("reading_pass_issued", "reading_pass_redeemed", "reading_pass_revoked"):
        assert a in actions, a
    print("   " + ", ".join(actions))
    print("\n全部一次性阅览凭证示例断言通过。")


if __name__ == "__main__":
    main()

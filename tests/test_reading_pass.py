"""一次性阅览凭证（reading pass）功能测试。

规则要点（规格）：
- 当前封存人凭资料编号签发不可猜测的一次性阅览凭证，截止时刻带时区、
  在未来且严格早于已安排的清除时刻；明文仅签发时返回，库内只存摘要；
  响应同时给出供撤销使用的凭证编号；
- 外部复核人无需账号，凭明文在截止前可读取一次正文及摘要；
  并发兑换至多一次成功；
- 当前封存人凭凭证编号可在兑换前撤销；
- 兑换前须在同一事务结算到期清除，清除时刻与兑换同刻以清除优先；
- 过期、撤销、已兑付、无效凭证或已清除资料统一拒绝，且不泄露正文或
  资料存在性（统一 403、统一文案）；
- 成功、签发和撤销均写入原有审计链；既有参与方读权限、清除和审计快照
  约定保持兼容。
"""
import datetime as dt
import os
import socket
import sqlite3
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor

import httpx
import pytest
from fastapi.testclient import TestClient

from conftest import auth, digest_of, register, seal

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

BODY = "一次性阅览绝密正文 READING-PASS-SECRET"


def _in_seconds(s: float) -> str:
    return (dt.datetime.now(dt.timezone.utc) + dt.timedelta(seconds=s)).isoformat()


def _in_hours(h: float) -> str:
    return (dt.datetime.now(dt.timezone.utc) + dt.timedelta(hours=h)).isoformat()


def _open_doc(client, keys, doc_id, dg, owner="owner", witnesses=("w1", "w2", "w3")):
    """走完整开封流程：owner 提请求，两名见证人各一票开封。"""
    r = client.post(
        f"/documents/{doc_id}/open-requests",
        json={"reason": "阅览凭证测试", "deadline": _in_hours(2)},
        headers=auth(keys[owner]),
    )
    assert r.status_code == 201, r.text
    req_id = r.json()["request_id"]
    for w in witnesses[:2]:
        assert client.post(
            f"/open-requests/{req_id}/approve", json={"digest": dg}, headers=auth(keys[w])
        ).status_code == 200


def _issue(client, key, doc_id, expires_at):
    return client.post(
        f"/documents/{doc_id}/reading-passes",
        json={"expires_at": expires_at},
        headers=auth(key),
    )


def _redeem(client, token):
    return client.post("/reading-passes/redeem", json={"token": token})


@pytest.fixture
def opened_setup(client):
    keys = {n: register(client, n) for n in ("owner", "w1", "w2", "w3", "other")}
    d = seal(client, keys["owner"], BODY, ["w1", "w2", "w3"])
    doc_id, dg = d["document_id"], d["digest"]
    _open_doc(client, keys, doc_id, dg)
    return keys, doc_id, dg


def test_issue_redeem_once(opened_setup, client):
    keys, doc_id, dg = opened_setup
    r = _issue(client, keys["owner"], doc_id, _in_hours(1))
    assert r.status_code == 201, r.text
    pkg = r.json()
    assert set(pkg) == {"pass_id", "document_id", "token", "expires_at", "status"}
    pass_id, token = pkg["pass_id"], pkg["token"]
    assert isinstance(pass_id, int)
    assert pkg["status"] == "active"
    # 不可猜测：256 位 hex
    assert len(token) == 64 and int(token, 16)

    # 外部复核人无账号：不带 X-API-Key 即可兑换，得到一次正文及摘要
    r = _redeem(client, token)
    assert r.status_code == 200, r.text
    got = r.json()
    assert got["body"] == BODY
    assert got["digest"] == dg
    assert got["status"] == "redeemed"
    assert got["pass_id"] == pass_id
    assert "redeemed_at" in got

    # 再次兑换：已兑付，统一 403
    r = _redeem(client, token)
    assert r.status_code == 403
    assert r.json() == {"detail": "阅览凭证无效或不可使用"}


def test_issue_validation(opened_setup, client):
    keys, doc_id, dg = opened_setup

    # 截止时刻必须在未来
    r = _issue(client, keys["owner"], doc_id, "2020-01-01T00:00:00Z")
    assert r.status_code == 400
    # 时间必须带时区
    r = _issue(client, keys["owner"], doc_id, "2030-01-01T00:00:00")
    assert r.status_code == 422

    # 已安排清除时刻：截止必须严格早于清除时刻（同刻也不行）
    purge_same = _in_hours(1)
    assert client.put(
        f"/documents/{doc_id}/purge", json={"purge_at": purge_same}, headers=auth(keys["owner"])
    ).status_code == 200
    assert _issue(client, keys["owner"], doc_id, purge_same).status_code == 400
    assert _issue(client, keys["owner"], doc_id, _in_hours(2)).status_code == 400
    ok = _issue(client, keys["owner"], doc_id, _in_seconds(10))
    assert ok.status_code == 201
    assert ok.json()["expires_at"] < purge_same


def test_issue_permissions_and_sealed_doc(client):
    keys = {n: register(client, n) for n in ("owner", "a", "b", "c", "x")}
    d = seal(client, keys["owner"], BODY, ["a", "b", "c"])
    doc_id = d["document_id"]

    # 资料未开封：不能签发
    assert _issue(client, keys["owner"], doc_id, _in_hours(1)).status_code == 409
    _open_doc(client, keys, doc_id, d["digest"], witnesses=("a", "b", "c"))

    # 只有当前封存人可签发
    assert _issue(client, keys["a"], doc_id, _in_hours(1)).status_code == 403
    assert _issue(client, keys["x"], doc_id, _in_hours(1)).status_code == 403
    # 无/错密钥
    assert client.post(
        f"/documents/{doc_id}/reading-passes", json={"expires_at": _in_hours(1)}
    ).status_code == 401
    assert _issue(client, "wrong-key", doc_id, _in_hours(1)).status_code == 401
    # 非参与方访问不存在资料：统一 403，不区分资料是否存在
    assert _issue(client, keys["x"], 999999, _in_hours(1)).status_code == 403


def test_denied_redeems_are_uniform_and_body_free(opened_setup, client):
    keys, doc_id, dg = opened_setup
    other_doc = seal(client, keys["other"], "另一份正文 OTHER-SECRET", ["w1", "w2", "w3"])

    # 无效/随机猜测的明文
    r = _redeem(client, "0" * 64)
    assert r.status_code == 403 and "body" not in r.text
    assert r.json() == {"detail": "阅览凭证无效或不可使用"}
    r = _redeem(client, "garbage")
    assert r.status_code == 403 and "body" not in r.text

    pkg = _issue(client, keys["owner"], doc_id, _in_hours(1)).json()

    # 见证人/其他账号的密钥对兑换没有任何意义（兑换本来就不需要凭据）；
    # 但错误的明文同样只能得到统一 403，不泄露 doc_id 或资料信息
    r = client.post(
        "/reading-passes/redeem",
        json={"token": pkg["token"] + "00"},
        headers=auth(keys["other"]),
    )
    assert r.status_code == 403
    assert str(doc_id) not in r.text and "digest" not in r.text
    assert r.json() == {"detail": "阅览凭证无效或不可使用"}


def test_revoke_before_redeem(opened_setup, client):
    keys, doc_id, dg = opened_setup
    pkg = _issue(client, keys["owner"], doc_id, _in_hours(1)).json()
    pass_id, token = pkg["pass_id"], pkg["token"]

    # 非封存人不能撤销；对不存在/无权的凭证编号统一 403
    assert client.post(
        f"/reading-passes/{pass_id}/revoke", headers=auth(keys["w1"])
    ).status_code == 403
    assert client.post(
        f"/reading-passes/{pass_id}/revoke", headers=auth(keys["other"])
    ).status_code == 403
    assert client.post("/reading-passes/999999/revoke", headers=auth(keys["owner"])).status_code == 403
    assert client.post(f"/reading-passes/{pass_id}/revoke").status_code == 401

    # 当前封存人撤销成功
    r = client.post(f"/reading-passes/{pass_id}/revoke", headers=auth(keys["owner"]))
    assert r.status_code == 200 and r.json()["status"] == "revoked"

    # 撤销后凭明文兑换被拒（与无效凭证同文案）
    r = _redeem(client, token)
    assert r.status_code == 403 and "body" not in r.text
    # 重复撤销 409；撤销已兑付的凭证 409
    assert client.post(
        f"/reading-passes/{pass_id}/revoke", headers=auth(keys["owner"])
    ).status_code == 409

    pkg2 = _issue(client, keys["owner"], doc_id, _in_hours(1)).json()
    assert _redeem(client, pkg2["token"]).status_code == 200
    assert client.post(
        f"/reading-passes/{pkg2['pass_id']}/revoke", headers=auth(keys["owner"])
    ).status_code == 409


def test_expired_pass_cannot_redeem(opened_setup, client):
    keys, doc_id, dg = opened_setup
    pkg = _issue(client, keys["owner"], doc_id, _in_seconds(1)).json()
    token = pkg["token"]
    # 过期是确定性派生状态：不依赖扫描器，等到截止时刻之后兑换必拒
    time.sleep(1.2)
    r = _redeem(client, token)
    assert r.status_code == 403 and "body" not in r.text
    # 过期后也不能撤销
    assert client.post(
        f"/reading-passes/{pkg['pass_id']}/revoke", headers=auth(keys["owner"])
    ).status_code == 409
    # 截止前的另一张凭证仍可正常兑付
    pkg2 = _issue(client, keys["owner"], doc_id, _in_hours(1)).json()
    assert _redeem(client, pkg2["token"]).status_code == 200


def test_redeem_settles_due_purge_same_instant_purge_wins(opened_setup, client, monkeypatch):
    """兑换前在同一事务结算到期清除；清除时刻与兑换同刻 -> 清除优先。"""
    keys, doc_id, dg = opened_setup
    # 扫描器不介入：靠兑换自身临界区做确定性清除
    monkeypatch.setenv("SWEEP_INTERVAL_SECONDS", "3600")
    pkg = _issue(client, keys["owner"], doc_id, _in_hours(1)).json()
    purge_at = client.put(
        f"/documents/{doc_id}/purge", json={"purge_at": _in_seconds(1)}, headers=auth(keys["owner"])
    ).json()["purge_at"]
    # 凭证截止时刻晚于清除时刻（发行时校验），等待清除时刻到达
    time.sleep(1.2)
    r = _redeem(client, pkg["token"])
    assert r.status_code == 403 and "body" not in r.text
    got = client.get(f"/documents/{doc_id}", headers=auth(keys["owner"])).json()
    assert got["status"] == "purged" and got["purged_at"] == purge_at


def test_issue_against_doc_purged_in_transaction(client, monkeypatch):
    """临界区内刚触发的清除先生效：签发 409，且不产生凭证。"""
    monkeypatch.setenv("SWEEP_INTERVAL_SECONDS", "3600")
    keys = {n: register(client, n) for n in ("pown", "pa", "pb", "pc")}
    d = seal(client, keys["pown"], BODY, ["pa", "pb", "pc"])
    _open_doc(client, keys, d["document_id"], d["digest"],
              owner="pown", witnesses=("pa", "pb", "pc"))
    assert client.put(
        f"/documents/{d['document_id']}/purge",
        json={"purge_at": _in_seconds(1)},
        headers=auth(keys["pown"]),
    ).status_code == 200
    time.sleep(1.2)
    r = _issue(client, keys["pown"], d["document_id"], _in_hours(1))
    assert r.status_code == 409 and "body" not in r.text


def test_issuance_revoke_redeem_in_audit_chain(opened_setup, client):
    keys, doc_id, dg = opened_setup
    pkg = _issue(client, keys["owner"], doc_id, _in_hours(1)).json()
    _redeem(client, pkg["token"])

    pkg2 = _issue(client, keys["owner"], doc_id, _in_hours(1)).json()
    client.post(f"/reading-passes/{pkg2['pass_id']}/revoke", headers=auth(keys["owner"]))

    records = client.get(f"/documents/{doc_id}/audit", headers=auth(keys["owner"])).json()["records"]
    actions = [(r["action"], r["actor"]) for r in records]
    assert ("reading_pass_issued", "owner") in actions
    assert ("reading_pass_redeemed", None) in actions   # 外部复核人无账号
    assert ("reading_pass_revoked", "owner") in actions
    # 审计 detail 不含明文 token（可带凭证编号）
    for r in records:
        if r["action"].startswith("reading_pass"):
            assert pkg["token"] not in r["detail"]
    # 审计序号严格递增、与既有审计同链
    seqs = [r["id"] for r in records]
    assert seqs == sorted(seqs) and len(seqs) == len(set(seqs))


def test_token_only_hash_in_database(opened_setup, client):
    """库内只存明文摘要：reading_passes 表只有哈希，全库搜不到明文。"""
    keys, doc_id, dg = opened_setup
    pkg = _issue(client, keys["owner"], doc_id, _in_hours(1)).json()
    token = pkg["token"]

    con = sqlite3.connect(os.environ["SEAL_DB_PATH"])
    row = con.execute(
        "SELECT token_hash, status FROM reading_passes WHERE id = ?", (pkg["pass_id"],)
    ).fetchone()
    import hashlib

    assert row == (hashlib.sha256(token.encode("utf-8")).hexdigest(), "active")
    # 全库任何文本字段都不出现明文 token
    tables = [r[0] for r in con.execute(
        "SELECT name FROM sqlite_master WHERE type='table'"
    ).fetchall()]
    for table in tables:
        cols = [c[1] for c in con.execute(f"PRAGMA table_info({table})")]
        for col in cols:
            hit = con.execute(
                f"SELECT COUNT(*) FROM {table} WHERE CAST({col} AS TEXT) LIKE ?",
                (f"%{token}%",),
            ).fetchone()[0]
            assert hit == 0, (table, col)
    con.close()


def test_existing_permissions_and_snapshot_unchanged(opened_setup, client):
    """凭证机制不改变参与方读权限；审计快照仍不含正文，可签发可验真。"""
    keys, doc_id, dg = opened_setup
    # 非参与方仍 403，不区分资料是否存在
    assert client.get(f"/documents/{doc_id}", headers=auth(keys["other"])).status_code == 403
    # 见证人读权限不变
    w = client.get(f"/documents/{doc_id}", headers=auth(keys["w1"]))
    assert w.status_code == 200 and w.json()["body"] == BODY

    pkg = _issue(client, keys["owner"], doc_id, _in_hours(1)).json()
    assert _redeem(client, pkg["token"]).status_code == 200

    # 快照签发/验真链路保持兼容
    r = client.post(
        f"/documents/{doc_id}/audit-snapshots", headers=auth(keys["owner"])
    )
    assert r.status_code == 201, r.text
    snap_pkg = r.json()
    assert "body" not in str(snap_pkg)
    pub = client.get("/audit-snapshots/public-key").json()
    r = client.post(
        "/audit-snapshots/verify",
        json={"snapshot": snap_pkg["snapshot"],
              "signature": snap_pkg["signature"],
              "public_key": pub["public_key"]},
    )
    assert r.status_code == 200 and r.json()["valid"] is True


def test_pass_management_tied_to_current_owner(client):
    """凭证的签发/撤销权绑定资料“当前封存人”：凭证是资料级凭据，编号不跨资料。

    交接仅对未开封资料开放，而阅览凭证只能对已开封资料签发，因此凭证存活期内
    封存人不会因交接改变；撤销权限始终按资料当前 owner_id 判定。
    """
    keys = {n: register(client, n) for n in ("o2", "e1", "e2", "e3", "o3", "f1", "f2", "f3")}
    d1 = seal(client, keys["o2"], BODY, ["e1", "e2", "e3"])
    _open_doc(client, keys, d1["document_id"], d1["digest"],
              owner="o2", witnesses=("e1", "e2", "e3"))
    d2 = seal(client, keys["o3"], "另一份正文", ["f1", "f2", "f3"])
    _open_doc(client, keys, d2["document_id"], d2["digest"],
              owner="o3", witnesses=("f1", "f2", "f3"))

    pkg1 = _issue(client, keys["o2"], d1["document_id"], _in_hours(1)).json()
    pkg2 = _issue(client, keys["o3"], d2["document_id"], _in_hours(1)).json()

    # 另一份资料的封存人不能撤销不属于自己资料的凭证（统一 403，不区分存在性）
    assert client.post(
        f"/reading-passes/{pkg1['pass_id']}/revoke", headers=auth(keys["o3"])
    ).status_code == 403
    assert client.post(
        f"/reading-passes/{pkg2['pass_id']}/revoke", headers=auth(keys["o2"])
    ).status_code == 403
    # 各自撤销自己资料的凭证成功；两张凭证互不影响
    assert client.post(
        f"/reading-passes/{pkg1['pass_id']}/revoke", headers=auth(keys["o2"])
    ).status_code == 200
    assert _redeem(client, pkg1["token"]).status_code == 403
    assert _redeem(client, pkg2["token"]).status_code == 200


# ---------------------------------------------------------------------------
# 真实 uvicorn + 多线程：并发兑换至多一次成功
# ---------------------------------------------------------------------------


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture
def live_server(tmp_path, monkeypatch):
    monkeypatch.setenv("SEAL_DB_PATH", str(tmp_path / "live-pass.db"))
    monkeypatch.setenv("SWEEP_INTERVAL_SECONDS", "3600")
    import uvicorn
    from app.main import app

    port = _free_port()
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning"))
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{port}"
    end = time.time() + 10
    while time.time() < end:
        try:
            if httpx.get(base + "/health", timeout=1).status_code == 200:
                break
        except Exception:
            time.sleep(0.1)
    else:
        pytest.fail("server did not start")
    yield base, str(tmp_path / "live-pass.db")
    server.should_exit = True
    thread.join(timeout=5)


def test_concurrent_redeem_single_success(live_server):
    base, db_path = live_server
    with httpx.Client(timeout=10) as c:
        def reg(name):
            return c.post(base + "/register", json={"username": name}).json()["api_key"]
        owner, w1, w2, w3 = (reg(n) for n in ("cown", "c1", "c2", "c3"))
        dg = digest_of(BODY)
        doc_id = c.post(
            base + "/documents", json={"body": BODY, "witnesses": ["c1", "c2", "c3"]},
            headers={"X-API-Key": owner},
        ).json()["document_id"]
        req_id = c.post(
            f"{base}/documents/{doc_id}/open-requests",
            json={"reason": "并发兑换", "deadline": _in_hours(2)},
            headers={"X-API-Key": owner},
        ).json()["request_id"]
        c.post(f"{base}/open-requests/{req_id}/approve", json={"digest": dg},
               headers={"X-API-Key": w1})
        c.post(f"{base}/open-requests/{req_id}/approve", json={"digest": dg},
               headers={"X-API-Key": w2})
        token = c.post(
            f"{base}/documents/{doc_id}/reading-passes",
            json={"expires_at": _in_hours(1)}, headers={"X-API-Key": owner},
        ).json()["token"]

    barrier = threading.Barrier(8)

    def redeem_once():
        barrier.wait()
        with httpx.Client(timeout=10) as cc:
            r = cc.post(base + "/reading-passes/redeem", json={"token": token})
            return r.status_code, (r.json().get("body") if r.status_code == 200 else None)

    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(lambda _: redeem_once(), range(8)))

    successes = [r for r in results if r[0] == 200]
    assert len(successes) == 1                       # 至多一次成功
    assert successes[0][1] == BODY                  # 成功者读到正文
    assert sum(1 for code, _ in results if code == 403) == 7

    # 库内终态：恰好一条 redeemed、一条兑付审计
    import hashlib

    token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
    con = sqlite3.connect(db_path)
    assert con.execute(
        "SELECT COUNT(*) FROM reading_passes WHERE token_hash = ? AND status='redeemed'",
        (token_hash,),
    ).fetchone()[0] == 1
    n_redeem_audit = con.execute(
        "SELECT COUNT(*) FROM audit_log WHERE document_id = ? AND action='reading_pass_redeemed'",
        (doc_id,),
    ).fetchone()[0]
    assert n_redeem_audit == 1
    con.close()

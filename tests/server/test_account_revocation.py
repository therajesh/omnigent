"""Account revocation across HTTP, credential, background, and launch boundaries."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from threading import Event

import pytest
from fastapi.testclient import TestClient

from tests.server.helpers import build_agent_bundle
from tests.server.test_accounts import _build_accounts_app, _login


def create_session(client):
    return client.post(
        "/v1/sessions",
        data={"metadata": "{}"},
        files={
            "bundle": ("agent.tar.gz", build_agent_bundle(name="review-agent"), "application/gzip")
        },
    )


@pytest.fixture
def setup_app(tmp_path, monkeypatch):
    import omnigent.server.app as app_module

    captured = {}
    original = app_module.create_app

    def capture(**kwargs):
        captured.update(kwargs)
        return original(**kwargs)

    monkeypatch.setattr(app_module, "create_app", capture)
    monkeypatch.delenv("OMNIGENT_OIDC_ISSUER", raising=False)
    yield_from = _build_accounts_app(tmp_path, monkeypatch, init_admin_password="admin-pw-12345")
    client = next(yield_from)
    try:
        admin = _login(client, "admin", "admin-pw-12345")
        invite = admin.post("/auth/invite", json={}).json()["token"]
        alice = TestClient(client.app)
        response = alice.post(
            "/auth/register",
            json={"invite": invite, "username": "alice", "password": "alice-pw-1234"},
        )
        assert response.status_code == 200, response.text
        yield admin, alice, captured, original
    finally:
        yield_from.close()


def test_login_cannot_issue_refresh_after_delete(setup_app, monkeypatch):
    import omnigent.server.routes.device_auth as device_auth

    admin, alice, stores, _ = setup_app
    reached, resume = Event(), Event()
    original_issue = device_auth.issue_login_grant

    def paused_issue(*args, **kwargs):
        reached.set()
        assert resume.wait(15)
        return original_issue(*args, **kwargs)

    monkeypatch.setattr(device_auth, "issue_login_grant", paused_issue)
    with ThreadPoolExecutor(max_workers=1) as pool:
        pending = pool.submit(
            alice.post,
            "/auth/login",
            json={"username": "alice", "password": "alice-pw-1234", "issue_refresh": True},
        )
        try:
            assert reached.wait(15)
            assert admin.delete("/auth/users/alice").status_code == 204
            assert stores["account_store"].get_user("alice") is None
        finally:
            resume.set()
        login = pending.result(timeout=15)
    assert login.status_code == 401, login.text
    assert "refresh_token" not in login.json()
    assert stores["account_store"].get_user("alice") is None
    assert create_session(alice).status_code == 401


def test_old_cookie_rejected_after_username_reuse(setup_app):
    admin, alice, _stores, _ = setup_app
    assert alice.get("/auth/me").status_code == 200
    assert admin.delete("/auth/users/alice").status_code == 204
    assert alice.get("/auth/me").status_code == 401
    invite = admin.post("/auth/invite", json={}).json()["token"]
    replacement = TestClient(admin.app)
    response = replacement.post(
        "/auth/register",
        json={"invite": invite, "username": "alice", "password": "different-password-1234"},
    )
    assert response.status_code == 200, response.text
    replay = alice.get("/auth/me")
    assert replay.status_code == 401, replay.text


def test_replica_cache_cannot_restore_account(setup_app):
    from omnigent.server.auth import create_auth_provider

    admin, alice, stores, create_app = setup_app
    replica_args = dict(stores)
    replica_auth = create_auth_provider()
    replica_args["auth_provider"] = replica_auth
    replica = TestClient(create_app(**replica_args))
    replica.cookies.update(alice.cookies)
    assert replica.get("/auth/me").status_code == 200
    assert admin.delete("/auth/users/alice").status_code == 204
    assert stores["account_store"].get_user("alice") is None
    created = create_session(replica)
    assert created.status_code == 401, created.text
    assert stores["account_store"].get_user("alice") is None
    replica_auth._cookie_cache.clear()
    assert replica.get("/auth/me").status_code == 401
    assert alice.get("/auth/me").status_code == 401


@pytest.mark.asyncio
@pytest.mark.parametrize("admitted", [False, True])
async def test_scheduled_dispatch_obeys_revocation_boundary(setup_app, monkeypatch, admitted):
    import asyncio
    import json
    import uuid

    from omnigent.host.frames import HostHelloFrame
    from omnigent.server.routes import _host_launch
    from omnigent.server.scheduled.fire import FireDeps, _make_connected_host_dispatch, _run_fire
    from omnigent.stores.scheduled_task_store.sqlalchemy_store import SqlAlchemyScheduledTaskStore

    admin, alice, stores, _ = setup_app
    created = create_session(alice)
    assert created.status_code == 201, created.text
    agent_id = created.json()["agent_id"]
    host_id = uuid.uuid4().hex
    host = stores["host_store"].upsert_on_connect(host_id, "review-host", "alice")
    registry = admin.app.state.host_registry
    from omnigent.db.account_authority import account_authority_scope

    with account_authority_scope("alice", host.account_generation):
        conn = registry.register(
            host_id,
            object(),
            HostHelloFrame(version="0.15.0", frame_protocol_version=1, name="review-host"),
            "alice",
        )
    tasks = SqlAlchemyScheduledTaskStore(str(stores["account_store"]._engine.url))
    task = tasks.create(
        uuid.uuid4().hex,
        "review-fire",
        "hello",
        "FREQ=DAILY",
        "alice",
        agent_id,
        "UTC",
        host_id=host_id,
        workspace="/tmp/review-workspace",
    )
    deps = FireDeps(
        scheduled_task_store=tasks,
        agent_store=stores["agent_store"],
        conversation_store=stores["conversation_store"],
        permission_store=stores["permission_store"],
        host_store=stores["host_store"],
        host_registry=registry,
    )
    reached, resume = Event(), Event()
    original_resolve = _host_launch.resolve_host_launch

    def pause_after_resolution(**kwargs):
        target = original_resolve(**kwargs)
        reached.set()
        assert resume.wait(15)
        return target

    if admitted:
        original_admit = registry.launch_authorizer

        def pause_after_admission(*args):
            original_admit(*args)
            reached.set()
            assert resume.wait(15)

        registry.launch_authorizer = pause_after_admission
    else:
        monkeypatch.setattr(_host_launch, "resolve_host_launch", pause_after_resolution)
    fire = asyncio.create_task(
        _run_fire(deps, 0, task.id, _make_connected_host_dispatch(deps), None)
    )
    try:
        assert await asyncio.to_thread(reached.wait, 10)
        deleted = await asyncio.to_thread(admin.delete, "/auth/users/alice")
        assert deleted.status_code == 204, deleted.text
        assert stores["account_store"].get_user("alice") is None
        assert stores["host_store"].get_host(host_id) is None
        assert tasks.get(task.id).state == "deleted"
        resume.set()
        if admitted:
            frame = json.loads(await asyncio.wait_for(conn.outbound_queue.get(), timeout=10))
            assert frame["kind"] == "host.launch_runner"
            conn.pending_launches.pop(frame["request_id"]).set_result(
                {"status": "failed", "error": "test transport: runner was not started"}
            )
        await asyncio.wait_for(fire, timeout=10)
        assert conn.outbound_queue.empty()
        runs, _ = tasks.list_runs(task.id)
        assert len(runs) == 1 and runs[0].status == "failed"
    finally:
        resume.set()
        if not fire.done():
            fire.cancel()
        await asyncio.gather(fire, return_exceptions=True)


@pytest.mark.parametrize("delete_during_request", [False, True])
def test_runner_token_uses_saved_account_authority(setup_app, monkeypatch, delete_during_request):
    import uuid

    from omnigent.runner.identity import RUNNER_TUNNEL_TOKEN_HEADER, token_bound_runner_id

    admin, alice, stores, _ = setup_app
    created = create_session(alice)
    assert created.status_code == 201, created.text
    session_id = created.json()["session_id"]
    binding = "test-runner-binding"
    runner_id = token_bound_runner_id(binding)
    host_id = uuid.uuid4().hex
    stores["host_store"].upsert_on_connect(host_id, "runner-host", "alice")
    conversations = stores["conversation_store"]
    conversations.set_host_id(session_id, host_id, workspace="/tmp/review-workspace")
    conversations.replace_runner_id(session_id, runner_id)
    runner = TestClient(admin.app)

    def mint():
        return runner.post(
            f"/v1/runners/{runner_id}/token",
            headers={RUNNER_TUNNEL_TOKEN_HEADER: binding},
        )

    issued = mint()
    assert issued.status_code == 200, issued.text
    runner.headers["Authorization"] = f"Bearer {issued.json()['token']}"
    assert runner.get("/auth/me").status_code == 200
    reached, resume = Event(), Event()
    original = stores["account_store"].with_runner_authority

    def paused(*args):
        reached.set()
        assert resume.wait(15)
        return original(*args)

    with ThreadPoolExecutor(max_workers=1) as pool:
        pending = None
        if delete_during_request:
            monkeypatch.setattr(stores["account_store"], "with_runner_authority", paused)
            pending = pool.submit(mint)
            assert reached.wait(15)
        try:
            assert admin.delete("/auth/users/alice").status_code == 204
            invite = admin.post("/auth/invite", json={}).json()["token"]
            replacement = TestClient(admin.app)
            assert (
                replacement.post(
                    "/auth/register",
                    json={"invite": invite, "username": "alice", "password": "new-password-1234"},
                ).status_code
                == 200
            )
        finally:
            resume.set()
        if pending is not None:
            assert pending.result(timeout=15).status_code == 401
    assert runner.get("/auth/me").status_code == 401
    assert mint().status_code == 401


def test_oauth_connection_state_cannot_cross_username_reuse(setup_app):
    from urllib.parse import parse_qs, urlsplit

    from omnigent.server.routes.connections_base import ConnectStart, create_connection_router

    admin, alice, stores, _ = setup_app
    completed = []

    class Provider:
        provider = "test-provider"
        store = None

        def signing_key(self):
            return b"test-state-key-32-bytes-long-12345"

        def begin(self, request, build_state):
            return ConnectStart(authorize_url=f"https://provider.example/?state={build_state({})}")

        async def complete(self, user_id, code, claims):
            completed.append(user_id)

    admin.app.include_router(
        create_connection_router(Provider(), auth_provider=stores["auth_provider"]), prefix="/v1"
    )
    started = alice.get("/v1/connections/test-provider/connect", follow_redirects=False)
    assert started.status_code == 302
    state = parse_qs(urlsplit(started.headers["location"]).query)["state"][0]
    callback = "/v1/connections/test-provider/callback"
    params = {"code": "test-provider-code", "state": state}
    assert (
        "connected"
        in alice.get(callback, params=params, follow_redirects=False).headers["location"]
    )
    assert completed == ["alice"]
    assert admin.delete("/auth/users/alice").status_code == 204
    invite = admin.post("/auth/invite", json={}).json()["token"]
    replacement = TestClient(admin.app)
    assert (
        replacement.post(
            "/auth/register",
            json={"invite": invite, "username": "alice", "password": "new-password-1234"},
        ).status_code
        == 200
    )
    assert (
        "error"
        in replacement.get(callback, params=params, follow_redirects=False).headers["location"]
    )
    assert completed == ["alice"]

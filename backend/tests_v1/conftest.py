"""Fixtures for the multi-tenant /api/v1 test suite."""

from __future__ import annotations

import os

import pytest
from alembic import command
from alembic.config import Config
from fastapi.testclient import TestClient
from sqlalchemy import text

from app.v1 import db as v1_db
from app.v1.db import Base

BACKEND_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PASSWORD = "Correct-Horse-Battery-42"


@pytest.fixture(scope="session", autouse=True)
def migrated_database():
    config = Config(os.path.join(BACKEND_DIR, "alembic.ini"))
    config.set_main_option("script_location", os.path.join(BACKEND_DIR, "migrations"))
    if v1_db.engine.dialect.name == "postgresql":
        with v1_db.engine.begin() as conn:
            for table in reversed(Base.metadata.sorted_tables):
                conn.execute(text(f'DROP TABLE IF EXISTS "{table.name}" CASCADE'))
            conn.execute(text("DROP TABLE IF EXISTS sc_alembic_version"))
    command.upgrade(config, "head")
    yield


@pytest.fixture(autouse=True)
def clean_tables(migrated_database):
    yield
    with v1_db.engine.begin() as conn:
        if conn.dialect.name == "postgresql":
            names = ", ".join(f'"{t.name}"' for t in Base.metadata.sorted_tables)
            conn.execute(text(f"TRUNCATE {names} RESTART IDENTITY CASCADE"))
        else:
            conn.execute(text("PRAGMA foreign_keys=OFF"))
            for table in reversed(Base.metadata.sorted_tables):
                conn.execute(table.delete())
            conn.execute(text("PRAGMA foreign_keys=ON"))


@pytest.fixture(autouse=True)
def no_real_github():
    """Tests must never reach the real GitHub API. Unless a test installs its
    own fake, every GitHub call is answered with 401 (as GitHub would for a
    made-up token), so results do not depend on network access."""
    import httpx

    from app.v1.services import github as gh

    gh.set_transport(httpx.MockTransport(lambda request: httpx.Response(401, json={"message": "Bad credentials"})))
    yield
    gh.set_transport(None)


@pytest.fixture(scope="session")
def app():
    from app.main import app as fastapi_app

    return fastapi_app


class ApiClient:
    """TestClient wrapper that remembers the CSRF token after sign-in."""

    def __init__(self, app):
        self.http = TestClient(app, base_url="http://testserver")
        self.csrf: str | None = None
        self.user: dict | None = None
        self.orgs: list = []

    def _headers(self, headers):
        merged = dict(headers or {})
        if self.csrf:
            merged.setdefault("X-CSRF-Token", self.csrf)
        return merged

    def get(self, url, **kw):
        return self.http.get(url, headers=self._headers(kw.pop("headers", None)), **kw)

    def post(self, url, **kw):
        return self.http.post(url, headers=self._headers(kw.pop("headers", None)), **kw)

    def patch(self, url, **kw):
        return self.http.patch(url, headers=self._headers(kw.pop("headers", None)), **kw)

    def put(self, url, **kw):
        return self.http.put(url, headers=self._headers(kw.pop("headers", None)), **kw)

    def delete(self, url, **kw):
        return self.http.delete(url, headers=self._headers(kw.pop("headers", None)), **kw)

    def absorb(self, response):
        body = response.json()
        if body.get("csrf_token"):
            self.csrf = body["csrf_token"]
        if "user" in body:
            self.user = body["user"]
            self.orgs = body["organizations"]
        return body

    def register(self, email, password=PASSWORD, name=""):
        response = self.post("/api/v1/auth/register", json={"email": email, "password": password, "display_name": name})
        assert response.status_code == 201, response.text
        return self.absorb(response)

    def login(self, email, password=PASSWORD):
        response = self.post("/api/v1/auth/login", json={"email": email, "password": password})
        if response.status_code == 200:
            self.absorb(response)
        return response


@pytest.fixture
def make_client(app):
    def factory():
        return ApiClient(app)

    return factory


@pytest.fixture
def owner(make_client):
    client = make_client()
    client.register("owner@alpha.example.com", name="Alpha Owner")
    org = client.post("/api/v1/organizations", json={"name": "Alpha Security"}).json()
    client.org_id = org["id"]
    return client


def invite_and_join(owner_client, make_client, email, role):
    response = owner_client.post(
        f"/api/v1/organizations/{owner_client.org_id}/invitations", json={"email": email, "role": role}
    )
    assert response.status_code == 201, response.text
    token = response.json()["accept_link"].split("token=", 1)[1]
    member = make_client()
    member.register(email)
    joined = member.post("/api/v1/invitations/accept", json={"token": token})
    assert joined.status_code == 200, joined.text
    member.org_id = owner_client.org_id
    return member

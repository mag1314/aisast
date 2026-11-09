"""Functional tests for AcmeShop (legitimate behaviour only).

AI-SAST runs these with `aisast fix --test-cmd "python -m pytest -q tests"` to prove a
security patch did not break normal functionality.
"""
import base64
import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
os.environ.setdefault("SECRET_KEY", "test-secret-key")
os.environ.setdefault("AWS_ACCESS_KEY_ID", "test-access-key")
os.environ.setdefault("JWT_SECRET", "test-jwt-secret")


@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("ACME_DB", str(tmp_path / "acme.db"))
    import importlib
    from app import db, main
    importlib.reload(db)
    importlib.reload(main)
    db.DB_PATH = str(tmp_path / "acme.db")
    db.init_db()
    c = db.conn()
    c.execute("INSERT INTO users (id, username, email, password_hash, role, balance) VALUES (1, 'alice', 'a@x.io', ?, 'customer', 100)",
              (db.hash_password("Wonderland!1"),))
    c.executemany("INSERT INTO products (id, name, price, created_at) VALUES (?, ?, ?, ?)",
                  [(1, "Laptop", 999.0, "2026-01-01"), (2, "Lamp", 25.0, "2026-02-01"), (3, "Mug", 9.5, "2026-03-01")])
    c.commit()
    os.makedirs(main.UPLOAD_DIR, exist_ok=True)
    with open(os.path.join(main.UPLOAD_DIR, "report.txt"), "w") as fh:
        fh.write("quarterly report")
    main.app.config["TESTING"] = True
    return main.app.test_client()


def test_login_success_and_failure(client):
    assert client.post("/login", data={"username": "alice", "password": "Wonderland!1"}).status_code == 200
    assert client.post("/login", data={"username": "alice", "password": "nope"}).status_code == 401
    assert client.post("/login", data={"username": "bob", "password": "x"}).status_code == 401


def test_search(client):
    names = {p["name"] for p in client.get("/search?q=La").get_json()}
    assert names == {"Laptop", "Lamp"}


def test_products_sorted_and_by_ids(client):
    assert [p["name"] for p in client.get("/products?sort=price").get_json()] == ["Mug", "Lamp", "Laptop"]
    assert len(client.get("/products/by-ids?ids=1,3").get_json()) == 2
    assert client.get("/products/2").get_json()["name"] == "Lamp"


def test_greetings_and_page(client):
    assert b"Ann" in client.get("/hello?name=Ann").data
    assert b"Ann" in client.get("/greet?name=Ann").data
    body = client.get("/page?title=Spring%20Sale").data
    assert b"Spring Sale" in body and b"42 products" in body


def test_download(client):
    r = client.get("/download?file=report.txt")
    assert r.status_code == 200 and r.data == b"quarterly report"


def test_redirects(client):
    assert client.get("/goto?next=/cart").headers["Location"].endswith("/cart")
    assert client.get("/continue?next=/home").headers["Location"].endswith("/home")


def test_settings_import(client):
    r = client.post("/settings/import", data="theme: dark\nitems: 3\n")
    assert sorted(r.get_json()["keys"]) == ["items", "theme"]


def test_calculator(client):
    assert client.post("/calc", data={"expr": "2 + 3 * 4"}).get_json()["result"] == 14
    assert client.post("/calc", data={"expr": "(10 - 4) / 3"}).get_json()["result"] == 2


def test_password_reset_token(client):
    assert client.post("/password/reset", data={"email": "a@x.io"}).get_json() == {"status": "sent"}
    from app import db
    token = db.conn().execute("SELECT reset_token FROM users WHERE id = 1").fetchone()[0]
    assert token and len(token) >= 16


def test_utils():
    from app import utils
    assert len(utils.generate_otp()) == 6 and utils.generate_otp().isdigit()
    assert len(utils.cache_key("/x")) == 32
    path = utils.scratch_file()
    assert path.endswith(".csv")

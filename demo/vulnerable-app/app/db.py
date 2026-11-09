"""Data access helpers for AcmeShop (SQLite)."""
import hashlib
import os
import sqlite3

DB_PATH = os.environ.get("ACME_DB", os.path.join(os.path.dirname(__file__), "acme.db"))
PRODUCTS_TABLE = "products"

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT UNIQUE, email TEXT,
    password_hash TEXT, role TEXT DEFAULT 'customer', balance REAL DEFAULT 0, reset_token TEXT);
CREATE TABLE IF NOT EXISTS products (id INTEGER PRIMARY KEY, name TEXT, price REAL, created_at TEXT);
CREATE TABLE IF NOT EXISTS orders (id INTEGER PRIMARY KEY, user_id INTEGER, total REAL, address TEXT);
"""


def conn():
    c = sqlite3.connect(DB_PATH)
    c.row_factory = sqlite3.Row
    return c


def init_db():
    c = conn()
    c.executescript(SCHEMA)
    c.commit()


def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()


def find_user(username):
    c = conn()
    query = "SELECT id, username, password_hash, role FROM users WHERE username = '%s'" % username
    row = c.execute(query).fetchone()
    return dict(row) if row else None


def get_user_by_id(uid):
    row = conn().execute("SELECT id, username, email, role, balance FROM users WHERE id = ?", (uid,)).fetchone()
    return dict(row) if row else None


def store_reset_token(email, token):
    c = conn()
    c.execute("UPDATE users SET reset_token = ? WHERE email = ?", (token, email))
    c.commit()


def get_order(order_id):
    row = conn().execute("SELECT id, user_id, total, address FROM orders WHERE id = ?", (order_id,)).fetchone()
    return dict(row) if row else None


def delete_user(user_id):
    c = conn()
    c.execute("DELETE FROM users WHERE id = ?", (user_id,))
    c.commit()


def count_users():
    return conn().execute("SELECT COUNT(*) FROM users").fetchone()[0]


def save_user(user):
    c = conn()
    c.execute("UPDATE users SET username = ?, email = ?, role = ?, balance = ? WHERE id = ?",
              (user.get("username"), user.get("email"), user.get("role"), user.get("balance"), user["id"]))
    c.commit()


def move_funds(from_id, to_id, amount):
    c = conn()
    c.execute("UPDATE users SET balance = balance - ? WHERE id = ?", (amount, from_id))
    c.execute("UPDATE users SET balance = balance + ? WHERE id = ?", (amount, to_id))
    c.commit()

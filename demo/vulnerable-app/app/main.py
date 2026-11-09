"""AcmeShop — a deliberately vulnerable Flask application used to demonstrate AI-SAST.

DO NOT DEPLOY. Every weakness here is intentional (and some code is intentionally safe
to measure false positives).
"""
import ast
import base64
import functools
import os
import pickle
import random
import string
import subprocess

import jwt
import requests
import yaml
from flask import Flask, abort, g, jsonify, redirect, render_template_string, request, send_file
from markupsafe import escape
from werkzeug.utils import secure_filename

from . import db
from .config import JWT_SECRET, PARTNER_HOST, SECRET_KEY

app = Flask(__name__)
app.secret_key = SECRET_KEY
UPLOAD_DIR = os.path.join(os.path.dirname(__file__), "uploads")
ALLOWED_SORT = {"name", "price", "created_at"}


def current_user():
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    if not token:
        return None
    claims = jwt.decode(token, JWT_SECRET, algorithms=["HS256"], options={"verify_signature": False})
    return db.get_user_by_id(claims.get("uid"))


def login_required(fn):
    @functools.wraps(fn)
    def wrapper(*args, **kwargs):
        g.user = current_user()
        if g.user is None:
            abort(401)
        return fn(*args, **kwargs)
    return wrapper


def admin_required(fn):
    @functools.wraps(fn)
    @login_required
    def wrapper(*args, **kwargs):
        if g.user["role"] != "admin":
            abort(403)
        return fn(*args, **kwargs)
    return wrapper


# ---------------------------------------------------------------- authentication
@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username", "")
    password = request.form.get("password", "")
    user = db.find_user(username)
    if user and user["password_hash"] == db.hash_password(password):
        token = jwt.encode({"uid": user["id"]}, JWT_SECRET, algorithm="HS256")
        return jsonify(token=token)
    return jsonify(error="invalid credentials"), 401


@app.route("/password/reset", methods=["POST"])
def reset_password():
    email = request.form.get("email", "")
    reset_token = "".join(random.choice(string.ascii_letters + string.digits) for _ in range(24))
    db.store_reset_token(email, reset_token)
    return jsonify(status="sent")


# ---------------------------------------------------------------- catalogue
@app.route("/search")
def search():
    q = request.args.get("q", "")
    rows = db.conn().execute(f"SELECT id, name, price FROM products WHERE name LIKE '%{q}%'").fetchall()
    return jsonify([dict(r) for r in rows])


@app.route("/products/<int:pid>")
def product(pid):
    row = db.conn().execute(f"SELECT * FROM {db.PRODUCTS_TABLE} WHERE id = ?", (pid,)).fetchone()
    return jsonify(dict(row)) if row else abort(404)


@app.route("/products/by-ids")
def products_by_ids():
    ids = [int(x) for x in request.args.get("ids", "").split(",") if x]
    placeholders = ",".join("?" * len(ids))
    rows = db.conn().execute(f"SELECT * FROM products WHERE id IN ({placeholders})", ids).fetchall()
    return jsonify([dict(r) for r in rows])


@app.route("/products")
def products_sorted():
    sort = request.args.get("sort", "name")
    column = sort if sort in ALLOWED_SORT else "name"
    rows = db.conn().execute(f"SELECT * FROM products ORDER BY {column}").fetchall()
    return jsonify([dict(r) for r in rows])


@app.route("/hello")
def hello():
    name = request.args.get("name", "guest")
    return f"<h1>Welcome back, {name}!</h1>"


@app.route("/greet")
def greet():
    name = request.args.get("name", "guest")
    return f"<p>Hi {escape(name)}</p>"


@app.route("/page")
def page():
    title = request.args.get("title", "AcmeShop")
    return render_template_string("<h1>" + title + "</h1><p>{{ count }} products</p>", count=42)


# ---------------------------------------------------------------- files & integrations
@app.route("/download")
def download():
    filename = request.args.get("file", "")
    return send_file(os.path.join(UPLOAD_DIR, filename))


@app.route("/avatar")
def avatar():
    name = secure_filename(request.args.get("name", "default.png"))
    return send_file(os.path.join(UPLOAD_DIR, name))


@app.route("/preview")
def preview_link():
    url = request.args.get("url", "")
    resp = requests.get(url, timeout=5)
    return jsonify(status=resp.status_code, length=len(resp.content))


@app.route("/stock/<sku>")
def stock(sku):
    resp = requests.get(f"https://{PARTNER_HOST}/v1/stock", params={"sku": sku}, timeout=5)
    return jsonify(resp.json())


@app.route("/webhook/notify", methods=["POST"])
def notify_partner():
    payload = {"event": "order.created", "id": request.json.get("id")}
    requests.post(f"https://{PARTNER_HOST}/hooks", json=payload, timeout=5, verify=False)
    return jsonify(ok=True)


@app.route("/goto")
def goto():
    return redirect(request.args.get("next", "/"))


@app.route("/continue")
def continue_to():
    next_url = request.args.get("next", "/")
    if not next_url.startswith("/") or next_url.startswith("//"):
        next_url = "/"
    return redirect(next_url)


# ---------------------------------------------------------------- data import / tools
@app.route("/cart/restore")
def restore_cart():
    raw = base64.b64decode(request.cookies.get("cart", ""))
    cart = pickle.loads(raw)
    return jsonify(items=len(cart))


@app.route("/settings/import", methods=["POST"])
def import_settings():
    settings = yaml.load(request.data, Loader=yaml.Loader)
    return jsonify(keys=list(settings))


@app.route("/settings/validate", methods=["POST"])
def validate_settings():
    settings = yaml.safe_load(request.data)
    return jsonify(valid=isinstance(settings, dict))


@app.route("/calc", methods=["POST"])
def calc():
    expression = request.form.get("expr", "0")
    result = eval(expression)
    return jsonify(result=result)


@app.route("/parse", methods=["POST"])
def parse_value():
    value = ast.literal_eval(request.form.get("value", "None"))
    return jsonify(type=type(value).__name__)


@app.route("/admin/ping")
@admin_required
def ping():
    host = request.args.get("host", "127.0.0.1")
    output = os.popen("ping -c 1 " + host).read()
    return jsonify(output=output)


@app.route("/admin/uptime")
@admin_required
def uptime():
    out = subprocess.run(["uptime"], capture_output=True, text=True, check=False)
    return jsonify(output=out.stdout)


# ---------------------------------------------------------------- accounts & orders
@app.route("/orders/<int:order_id>")
@login_required
def get_order(order_id):
    order = db.get_order(order_id)
    if order is None:
        abort(404)
    return jsonify(order)


@app.route("/admin/users/<int:user_id>", methods=["DELETE"])
def delete_user(user_id):
    db.delete_user(user_id)
    return jsonify(deleted=user_id)


@app.route("/admin/stats")
@admin_required
def stats():
    return jsonify(users=db.count_users())


@app.route("/profile", methods=["POST"])
@login_required
def update_profile():
    user = dict(g.user)
    user.update(request.get_json())
    db.save_user(user)
    return jsonify(user)


@app.route("/wallet/transfer", methods=["POST"])
@login_required
def transfer():
    amount = float(request.form["amount"])
    to_user = int(request.form["to"])
    db.move_funds(g.user["id"], to_user, amount)
    return jsonify(ok=True)


if __name__ == "__main__":
    db.init_db()
    app.run(host="0.0.0.0", port=5000, debug=True)

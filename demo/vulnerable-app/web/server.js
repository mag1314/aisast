// AcmeShop partner API (Express) — deliberately vulnerable. DO NOT DEPLOY.
const express = require("express");
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");
const { exec, execFile } = require("child_process");
const axios = require("axios");
const jwt = require("jsonwebtoken");
const _ = require("lodash");
const serialize = require("node-serialize");
const mysql = require("mysql");
const { User, Order } = require("./models");

const app = express();
app.use(express.json());

const db = mysql.createConnection({ host: "localhost", user: "acme", database: "acme" });
const JWT_SECRET = "acme-jwt-signing-secret-4b9f2e71c0";
const settings = { theme: "light" };

function hashPassword(password) {
  return crypto.createHash("md5").update(password).digest("hex");
}

function etagFor(buffer) {
  return crypto.createHash("sha1").update(buffer).digest("hex");
}

app.get("/api/users/search", (req, res) => {
  const name = req.query.name;
  db.query("SELECT id, name FROM users WHERE name = '" + name + "'", (err, rows) => res.json(rows));
});

app.get("/api/users/:id", (req, res) => {
  db.query("SELECT id, name FROM users WHERE id = ?", [req.params.id], (err, rows) => res.json(rows));
});

app.post("/api/login", async (req, res) => {
  const user = await User.findOne({ username: req.body.username, password: hashPassword(req.body.password) });
  if (!user) return res.status(401).end();
  res.json({ token: jwt.sign({ uid: user.id }, JWT_SECRET) });
});

app.post("/api/thumbnail", (req, res) => {
  exec("convert " + req.body.file + " -resize 64x64 thumb.png", (err, out) => res.send(out));
});

app.post("/api/thumbnail-safe", (req, res) => {
  execFile("convert", [path.basename(req.body.file), "-resize", "64x64", "thumb.png"], (err, out) => res.json({ ok: !err }));
});

app.get("/api/results", (req, res) => {
  const term = req.query.term;
  res.send(`<h2>Results for ${term}</h2>`);
});

app.get("/api/results.json", (req, res) => {
  res.json({ term: req.query.term });
});

app.get("/api/files", (req, res) => {
  fs.readFile(path.join(__dirname, "files", req.query.name), (err, data) => res.send(data));
});

app.get("/api/files-safe", (req, res) => {
  const name = path.basename(req.query.name);
  fs.readFile(path.join(__dirname, "files", name), (err, data) => res.send(data));
});

app.get("/api/proxy", async (req, res) => {
  const target = req.query.url;
  const r = await axios.get(target);
  res.json(r.data);
});

app.post("/api/formula", (req, res) => {
  const result = eval(req.body.formula);
  res.json({ result });
});

app.post("/api/session", (req, res) => {
  const sessionToken = Math.random().toString(36).slice(2);
  res.cookie("sid", sessionToken);
  res.json({ ok: true });
});

app.post("/api/settings", (req, res) => {
  _.merge(settings, req.body);
  res.json(settings);
});

app.get("/api/redirect", (req, res) => {
  res.redirect(req.query.to);
});

app.get("/api/profile", (req, res) => {
  const profile = serialize.unserialize(Buffer.from(req.cookies.profile, "base64").toString());
  res.json(profile);
});

app.get("/api/me", (req, res) => {
  const claims = jwt.decode(req.headers.authorization);
  res.json({ uid: claims.uid });
});

app.get("/api/orders/:id", async (req, res) => {
  const order = await Order.findById(req.params.id);
  res.json(order);
});

app.get("/api/assets/:file", (req, res) => {
  const data = fs.readFileSync(path.join(__dirname, "assets", "logo.png"));
  res.set("ETag", etagFor(data)).send(data);
});

app.listen(3000);

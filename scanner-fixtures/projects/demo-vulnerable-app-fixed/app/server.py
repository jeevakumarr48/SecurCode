import hashlib
import sqlite3
import subprocess

import requests
from flask import Flask, redirect, request, url_for

app = Flask(__name__)
ALLOWED_HOSTS = {"example.org", "example.net"}


@app.route("/user")
def user():
    connection = sqlite3.connect("app.db")
    user_id = request.args.get("id")
    return str(connection.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchall())


@app.route("/ping")
def ping():
    host = request.args.get("host")
    if host not in ALLOWED_HOSTS:
        return "host not allowed", 400
    return subprocess.run(["ping", "-c", "1", host], capture_output=True).stdout


@app.route("/next")
def go_next():
    return redirect(url_for("index"))


def checksum(data):
    return hashlib.md5(data).hexdigest()


def fetch_partner():
    return requests.get("https://partner.example.net/api", timeout=5)

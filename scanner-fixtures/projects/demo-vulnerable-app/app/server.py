import hashlib
import sqlite3
import subprocess

import requests
from flask import Flask, redirect, request

app = Flask(__name__)


@app.route("/user")
def user():
    connection = sqlite3.connect("app.db")
    user_id = request.args.get("id")
    return str(connection.execute(f"SELECT * FROM users WHERE id = {user_id}").fetchall())


@app.route("/ping")
def ping():
    host = request.args.get("host")
    return subprocess.run(f"ping -c 1 {host}", shell=True, capture_output=True).stdout


@app.route("/next")
def go_next():
    return redirect(request.args.get("next"))


def checksum(data):
    return hashlib.md5(data).hexdigest()


def fetch_partner():
    return requests.get("https://partner.example.net/api", verify=False)

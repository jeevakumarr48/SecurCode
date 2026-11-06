import requests
from flask import request

target = request.args.get("url")
requests.get(
    target,
    timeout=2,
)

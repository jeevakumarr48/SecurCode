import logging
import os
import tarfile

from flask import Flask, redirect, request
from lxml import etree

app = Flask(__name__)
DEBUG = True  # expect: PYSEC016
SESSION_COOKIE_SECURE = False  # expect: PYSEC018
WTF_CSRF_ENABLED = False  # expect: PYSEC018
logger = logging.getLogger(__name__)


@app.route("/next")
def go_next():
    return redirect(request.args.get("next"))  # expect: PYSEC017


def login(username, password):
    logger.info("login attempt %s %s", username, password)  # expect: PYSEC020
    os.chmod("/srv/app/config.ini", 0o777)  # expect: PYSEC022


def unpack(upload):
    with tarfile.open(upload) as archive:
        archive.extractall("/tmp/out")  # expect: PYSEC023


parser = etree.XMLParser(resolve_entities=True)  # expect: PYSEC024
AWS_ACCESS = "AKIAIOSFODNN7EXAMPLA"  # expect: PYSEC025

if __name__ == "__main__":
    app.run(host="0.0.0.0", debug=True)  # expect: PYSEC016 PYSEC026

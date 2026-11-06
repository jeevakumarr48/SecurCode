import sqlite3
from flask import request

connection = sqlite3.connect(":memory:")
query_input = request.args.get("query")
query_alias = query_input


def run_report(statement):
    connection.execute(statement)


run_report(f"SELECT * FROM reports WHERE title = '{query_alias}'")

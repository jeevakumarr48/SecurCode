from security_engine.scanner.python import scan_python_file


def _scan(tmp_path, source):
    target = tmp_path / "tainted.py"
    target.write_text(source, encoding="utf-8")
    return scan_python_file(str(target))


def _rules(findings):
    return {finding["test_id"] for finding in findings}


def test_tracks_request_input_through_alias_and_multiline_sql(tmp_path):
    findings = _scan(tmp_path, """
import request_context as ctx
request = ctx.request
user_id = request.args.get("id")
query = ("SELECT * FROM users WHERE id = "
         + user_id)
cursor.execute(query)
""")

    finding = next(item for item in findings if item["test_id"] == "PYSEC007")
    assert finding["cwe"] == "CWE-89"
    assert finding["evidence"]["source_lines"] == [4]
    assert finding["evidence"]["sink_line"] == 7


def test_tracks_aliases_to_shell_command_sink_and_respects_shell_quote(tmp_path):
    unsafe = _scan(tmp_path, """
import subprocess as sp
from builtins import input as ask
command = ask()
sp.run(command, shell=True)
""")
    assert "PYSEC008" in _rules(unsafe)

    safe = _scan(tmp_path, """
import subprocess as sp
import shlex as shell
command = shell.quote(input())
sp.run(command, shell=True)
""")
    assert "PYSEC008" not in _rules(safe)


def test_tracks_path_and_ssrf_sinks_but_not_parameterized_sql(tmp_path):
    findings = _scan(tmp_path, """
from pathlib import Path
import requests
url = input()
path = input()
requests.get(url)
open(path)
cursor.execute("SELECT * FROM users WHERE id = ?", (url,))
""")

    assert {"PYSEC009", "PYSEC010"}.issubset(_rules(findings))
    assert "PYSEC007" not in _rules(findings)


def test_recognizes_path_basename_sanitization(tmp_path):
    findings = _scan(tmp_path, """
import os.path as paths
filename = paths.basename(input())
open(filename)
""")

    assert "PYSEC009" not in _rules(findings)


def test_tracks_taint_through_common_wrapper_parameters(tmp_path):
    findings = _scan(tmp_path, """
import subprocess
def execute_user_command(command):
    subprocess.run(command, shell=True)
execute_user_command(input())
""")

    finding = next(item for item in findings if item["test_id"] == "PYSEC008")
    assert finding["evidence"]["source_lines"] == [5]

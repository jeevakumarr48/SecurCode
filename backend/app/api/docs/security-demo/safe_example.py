import json
import subprocess

def parse_user_data(user_input: str):
    return json.loads(user_input)

def run_fixed_command():
    return subprocess.run(
        ["python", "--version"],
        shell=False,
        check=True,
        capture_output=True,
        text=True,
    )

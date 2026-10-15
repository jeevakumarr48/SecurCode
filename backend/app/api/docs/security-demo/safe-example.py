
import json
import subprocess


def parse_user_data(user_input: str):
    """Parse JSON without evaluating arbitrary Python code."""
    return json.loads(user_input)


def run_fixed_command():
    """Run a fixed command without invoking a shell."""
    return subprocess.run(
        ["python", "--version"],
        shell=False,
        check=True,
        capture_output=True,
        text=True,
    )

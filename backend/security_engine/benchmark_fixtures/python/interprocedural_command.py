import subprocess
from flask import request


def launch(command_text):
    subprocess.run(command_text, shell=True)


user_command = request.args.get("command")
launch(user_command)

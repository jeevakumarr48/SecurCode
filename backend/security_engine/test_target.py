
import subprocess

user_input = "print('hello')"
eval(user_input)

subprocess.call("echo hello", shell=True)

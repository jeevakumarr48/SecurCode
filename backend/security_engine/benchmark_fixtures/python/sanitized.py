import os.path as paths
import shlex
import subprocess

command = shlex.quote(input())
subprocess.run(command, shell=True)
filename = paths.basename(input())
open(filename)
service.run(input(), shell=True)

import requests
import subprocess

query_value = input()
query = f"SELECT * FROM accounts WHERE name = '{query_value}'"
cursor.execute(query)

command = input()
subprocess.run(command, shell=True)

remote_url = input()
requests.get(remote_url)

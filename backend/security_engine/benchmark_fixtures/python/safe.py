import requests
import subprocess

account_id = int(input())
cursor.execute("SELECT * FROM accounts WHERE id = ?", (account_id,))

subprocess.run(["/usr/bin/id", "-u"], shell=False)
requests.get("https://api.example.test/health")

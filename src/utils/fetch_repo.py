import os

import requests
import dotenv



dotenv.load_dotenv(".env")

def is_py_file(file):
    return file["name"].endswith(".py") and file["type"] == "file" and file['name'] != '__init__.py'


def extract_repo_python_files(items):
    for item in items:
        if is_py_file(item):
            yield item
        
        if item['type'] == 'dir':
            subdir_url = item['url']
            resp = requests.get(subdir_url, headers=headers)
            resp.raise_for_status()
            yield from extract_repo_python_files(resp.json())

headers = {
    "Authorization": f"Bearer {os.getenv('GITHUB_ACCESS_TOKEN')}"
}

github_user = "Shreejal170"
github_repo = "DjangoChatApp"

url = f"https://api.github.com/repos/{github_user}/{github_repo}/contents"

resp = requests.get(url, headers=headers)
resp.raise_for_status()

py_files = list(extract_repo_python_files(resp.json()))
# py_files = [item for item in resp.json()]

with open ("data.json", "w") as f:
    import json
    json.dump(py_files, f, indent=4)

for item in py_files:
    print(item["name"], item["type"])


print(item["download_url"])




def fetch_repo_contents(github_user, github_repo):
    url = f"https://api.github.com/repos/{github_user}/{github_repo}/contents"
    resp = requests.get(url, headers=headers)
    resp.raise_for_status()
    return list(extract_repo_python_files(resp.json()))
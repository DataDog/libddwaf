"""
Helper for running fuzz targets in the internal fuzzing infrastructure.
"""

import os
import sys
import base64

import requests

# replace me to "k9-libddwaf" once CHAOSPLT-991 is fixed. Lets not send empty bugreport to end users slacks
SLACK_CHANNEL = "fuzzing-ops"
REPOSITORY_URL = "https://github.com/DataDog/libddwaf"

BUILD_BASE_PATH = "/workspace/build"
FUZZER_BASE_PATH = "/workspace/fuzzer"
BUILD_SCRIPT_PATH = "/workspace/fuzzer/build.sh"
CORPUS_PATH_PATTERN = "/workspace/{}/corpus"
API_URL = "https://fuzzing-api.us1.ddbuild.io/api/v1"
MAX_PKG_NAME_LENGTH = 50

def build_and_upload_fuzz(team="k9-libddwaf", core_count=2, duration=3600, proc_count=2, memory=4):
    """
    This builds and uploads fuzz targets to the internal fuzzing infrastructure.
    It needs to be passed the -fuzz flag in order to build the fuzz with efficient coverage guidance.
    """

    git_sha = os.popen("git rev-parse HEAD").read().strip()

    build_all()

    binaries = search_fuzzers(BUILD_BASE_PATH)
    if len(binaries) == 0:
        print(f"❌ Found {len(binaries)} fuzzers!")
        print("Files available in searched path: ", BUILD_BASE_PATH)
        for f in os.listdir(BUILD_BASE_PATH):
            print(f" - {f}")
        return

    print(f"✅ Found {len(binaries)} fuzzers (e.g: {binaries[:5]}...)")
    for binary in binaries:
        pkgname = get_package_name(binary)
        build_full_path = os.path.join(BUILD_BASE_PATH, binary)
        print(f"Handling {pkgname} ({binary}) build_full_path: {build_full_path}")
        if not os.path.exists(build_full_path):
            print(f'❌ Build file {build_full_path} does not exist. Skipping...')
            continue

        print(f"Uploading corpus for {pkgname} ({binary})...")
        has_error = upload_corpus(pkgname, binary)
        if has_error:
            print(f'❌ Failed to upload corpus for {pkgname} ({binary}). Skipping fuzzer start...')
        else:
            print(f"✅ Uploaded corpus for {pkgname} ({binary})")

        print(f"Uploading binary for {pkgname} ({binary})...")
        has_error = upload_binary(pkgname, binary, git_sha)
        if has_error:
            print(f'❌ Failed to upload binary for {pkgname}. Aborting')
            return
        else:
            print(f"✅ Uploaded binary for {pkgname} ({binary})")

        print(f"Starting fuzzer for {pkgname} ({binary})...")
        has_error = create_fuzzer(pkgname, binary, git_sha, core_count, duration, proc_count, memory, team, SLACK_CHANNEL, REPOSITORY_URL)
        if has_error:
            print(f'❌ Failed to create fuzzer for {pkgname} ({binary})')
        else:
            print(f"✅ Fuzzer created for {pkgname} ({binary})")

def upload_corpus(pkgname, binary) -> bool:
    has_errors = False
    corpus_files_path = search_corpus(binary.replace("_fuzzer", ""))
    print(f'Uploading corpus (count: {len(corpus_files_path)}) for {pkgname} ({binary})...')

    # Get headers only once, so we don't have to call vault every time we upload a file
    # Our current api doesn't support archive / batch upload yet (WIP)
    headers = get_headers()
    for file in corpus_files_path:
        with open(file, "rb") as f:
            data = f.read()
            data = {
                "content": base64.b64encode(data).decode("utf-8"),
            }
            try:
                response = requests.post(f"{API_URL}/apps/{pkgname}/inputs", headers=headers, json=data, timeout=30)
                response.raise_for_status()
            except Exception as e:
                print(f'❌ Failed to upload file for corpus, {pkgname} ({binary}): {e}')
                print("Ignoring this file and continuing...")
                has_errors = True
                continue

    print(f'✅ Uploaded corpus for {pkgname} ({binary})...')
    return has_errors

def build_all():
    print("Building all fuzzers in path: ", os.getcwd())
    os.system(BUILD_SCRIPT_PATH)
    print("✅ Built all fuzzers")

def get_package_name(binary):
    base = os.path.basename(binary)
    name = base.replace("_fuzzer", "")
    return "libddwaf-" + name[:MAX_PKG_NAME_LENGTH].replace("_", "-") # limit to 50 chars

def search_fuzzers(directory):
    def is_executable(file_path):
        return os.path.isfile(file_path) and os.access(file_path, os.X_OK)

    binaries = []
    if not os.path.isdir(directory):
        print(f"❌ Provided path {directory} is not a directory")
        return binaries

    for root, _, files in os.walk(directory):
        for fname in files:
            if not fname.endswith("_fuzzer"):
                continue
            fpath = os.path.join(root, fname)
            print(f"Checking fuzzer at path: {fpath}")
            if not is_executable(fpath):
                print(f"Skipping {fpath} because it's not executable")
                continue
            rel = os.path.relpath(fpath, directory)
            print(f"Adding {rel} to list of fuzzers")
            binaries.append(rel)
    return binaries

# search for all file in the "corpus" subdirectory of the app, return a list of files
def search_corpus(appname):
    corpus_path = CORPUS_PATH_PATTERN.format(appname)
    print(f"Searching for corpus in {corpus_path}")
    corpus_files_path = []
    if os.path.isdir(corpus_path):
        for filename in os.listdir(corpus_path):
            file_path = os.path.join(corpus_path, filename)
            if os.path.isfile(file_path):
                corpus_files_path.append(file_path)
    
    return corpus_files_path

def create_fuzzer(pkgname, binary, git_sha, core_count, duration, proc_count, memory, team, slack_channel, repository_url) -> bool:
    print(f'Starting fuzzer for {pkgname} ({binary})...')
    # Start new fuzzer
    run_payload = {
        "app": pkgname,
        "debug": False,
        "version": git_sha,
        "core_count": core_count,
        "duration": duration,
        "type": "libfuzzer",
        "binary": binary,
        "team": team,
        "process_count": proc_count,
        "memory": memory,
        "slack_channel": SLACK_CHANNEL,
        "repository_url": "https://github.com/DataDog/libddwaf",
    }
    try:
        response = requests.post(f"{API_URL}/apps/{pkgname}/fuzzers", headers=get_headers(), json=run_payload, timeout=30)
        response.raise_for_status()
        print(f'✅ Started fuzzer for {pkgname} ({binary})...')
        print(response.json())
    except Exception as e:
        print(f'❌ Failed to start fuzzer for {pkgname} ({binary}): {e}')
        return True

    return False

def upload_binary(pkgname, binary, git_sha) -> bool:
    try:
        # Get presigned URL so we can use s3 uploading
        print(f'Getting presigned URL for {pkgname}...')
        presigned_response = requests.post(
            f"{API_URL}/apps/{pkgname}/builds/{git_sha}/url", headers=get_headers(), timeout=30
        )
        presigned_response.raise_for_status()
        presigned_url = presigned_response.json()["data"]["url"]

        print(f'Uploading {pkgname} ({binary}) for {git_sha}...')
        # Upload file to presigned URL
        build_full_path = os.path.join(BUILD_BASE_PATH, binary)
        with open(build_full_path, 'rb') as f:
            upload_response = requests.put(presigned_url, data=f, timeout=300)
            upload_response.raise_for_status()
    except Exception as e:
        print(f'❌ Failed to upload binary for {pkgname} ({binary}): {e}')
        return True
    return False

def get_headers():
    auth_header = os.popen("vault read -field=token identity/oidc/token/security-fuzzing-platform").read().strip()
    return {"Authorization": f"Bearer {auth_header}", "Content-Type": "application/json"}

if __name__ == "__main__":
    print("🚀 Starting fuzzing infrastructure setup...")
    try:
        build_and_upload_fuzz()
        print("✅ Fuzzing infrastructure setup completed successfully!")
    except Exception as e:
        print(f"❌ Failed to set up fuzzing infrastructure: {e}")
        sys.exit(1)
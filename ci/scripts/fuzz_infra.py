"""
Helper for running fuzz targets in the internal fuzzing infrastructure.
"""

import os
import sys

import requests

# replace me to "k9-libddwaf" once CHAOSPLT-991 is fixed. Lets not send empty bugreport to end users slacks
SLACK_CHANNEL = "fuzzing-ops"
REPOSITORY_URL = "https://github.com/DataDog/libddwaf"

BUILD_BASE_PATH = "/workspace/fuzzer/build"
FUZZER_BASE_PATH = "/workspace/fuzzer"
CORPUS_PATH_PATTERN = "/workspace/fuzzer/{}/corpus"
API_URL = "https://fuzzing-api.us1.ddbuild.io/api/v1"

def build_and_upload_fuzz(team="k9-libddwaf", core_count=2, duration=3600, proc_count=2, memory=4):
    """
    This builds and uploads fuzz targets to the internal fuzzing infrastructure.
    It needs to be passed the -fuzz flag in order to build the fuzz with efficient coverage guidance.
    """

    git_sha = os.popen("git rev-parse HEAD").read().strip()

    build_all()

    max_pkg_name_length = 50
    binaries = search_fuzz_tests(BUILD_BASE_PATH)
    for binary in binaries:
        pkgname = "libddwaf-" + binary.replace("_fuzz", "")[:max_pkg_name_length].replace("_", "-") # limit to 50 chars
        print(f'Building {pkgname}, {BUILD_BASE_PATH}/{binary} for {git_sha}...')
        build_full_path = os.path.join(BUILD_BASE_PATH, binary)
        if not os.path.exists(build_full_path):
            print(f'❌ Build file {build_full_path} does not exist. Skipping...')
            continue

        upload_corpus(FUZZER_BASE_PATH, pkgname, binary)

        if upload_binary(pkgname, binary, git_sha):
            create_fuzzer(pkgname, binary, git_sha, core_count, duration, proc_count, memory, team, SLACK_CHANNEL, REPOSITORY_URL)
        else:
            print(f'❌ Failed to upload binary for {pkgname}. Skipping fuzzer start...')

def upload_corpus(basedir, pkgname, binary):
    corpus_files_path = search_corpus(os.path.join(basedir, binary.replace("_fuzz", ""), "corpus"))
    print(f'Uploading corpus (count: {len(corpus_files_path)}) for {pkgname} ({binary})...')

    # Our current api doesn't support archive / batch upload.
    for file in corpus_files_path:
        with open(file, "rb") as f:
            data = f.read()
            data = {
                "content": data,
            }
            try:
                response = requests.post(f"{API_URL}/apps/{pkgname}/inputs", headers=get_headers(), json=data, timeout=30)
                response.raise_for_status()
            except Exception as e:
                print(f'❌ Failed to upload file for corpus, {pkgname} ({binary}): {e}')
                print("Ignoring this file and continuing...")
                continue

    print(f'✅ Uploaded corpus for {pkgname} ({binary})...')

def build_all():
    print("Building all fuzzers in path: ", os.getcwd())
    os.system("./ci/scripts/fuzzer_build.sh")

def search_fuzz_tests(directory):
    def is_executable(file_path):
        return os.path.isfile(file_path) and os.access(file_path, os.X_OK)

    binaries = []
    if os.path.isdir(directory):
        for fname in os.listdir(directory):
            fpath = os.path.join(directory, fname)
            if is_executable(fpath) and fname.endswith("_fuzz"):
                binaries.append(fname)
    return binaries

# search for all file in the "corpus" subdirectory of the app, return a list of files
def search_corpus(appname):
    corpus_path = CORPUS_PATH_PATTERN.format(appname)
    corpus_files_path = []
    if os.path.isdir(corpus_path):
        for filename in os.listdir(corpus_path):
            file_path = os.path.join(corpus_path, filename)
            if os.path.isfile(file_path):
                corpus_files_path.append(file_path)
    
    return corpus_files_path

def create_fuzzer(pkgname, binary, git_sha, core_count, duration, proc_count, memory, team, slack_channel, repository_url):
    print(f'Starting fuzzer for {pkgname} ({binary})...')
    # Start new fuzzer
    run_payload = {
        "app": pkgname,
        "debug": False,
        "version": git_sha,
        "core_count": core_count,
        "duration": duration,
        "type": "aflpp",
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
        return False
    return True

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
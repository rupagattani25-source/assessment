import os
import json
import time
import base64
import hashlib
import requests
from dotenv import load_dotenv

from find_hidden_word import find_layer3_hidden_word


load_dotenv()

print("BASE_URL:", os.getenv("BASE_URL"))
print("API_KEY loaded:", bool(os.getenv("API_KEY")))

BASE_URL = os.getenv("BASE_URL")
API_KEY = os.getenv("API_KEY")

HEADERS = {
    "Authorization": f"Bearer {API_KEY}",
    "Accept": "application/json"
}


def get(path):
    url = f"{BASE_URL}{path}"
    response = requests.get(url, headers=HEADERS)

    print(f"GET {path} -> {response.status_code}")

    if response.status_code == 429:
        retry_after = int(response.headers.get("Retry-After", "1"))
        print(f"Rate limited. Waiting {retry_after} seconds...")
        time.sleep(retry_after)
        return get(path)

    if response.status_code >= 400:
        print("Error response:")
        print(response.text)
        print("Headers:")
        print(dict(response.headers))

    response.raise_for_status()
    return response


def post(path, payload):
    url = f"{BASE_URL}{path}"
    response = requests.post(url, headers={**HEADERS, "Content-Type": "application/json"}, json=payload)
    print(f"POST {path} -> {response.status_code}")

    try:
        print(json.dumps(response.json(), indent=2))
    except Exception:
        print(response.text)

    return response


def fetch_dataset():
    all_records = []

    ranges = [
        "0-99",
        "100-199",
        "200-299",
        "300-399",
        "400-499"
    ]

    for r in ranges:
        encoded_range = r.replace("-", "%2D")
        response = get(f"/api/v1/dataset?batch=true&range={encoded_range}")
        data = response.json()["data"]
        print(f"Fetched range {r}: {len(data)} records")
        all_records.extend(data)

    print(f"Total records fetched: {len(all_records)}")

    with open("encrypted_dataset.json", "w", encoding="utf-8") as f:
        json.dump(all_records, f, indent=2)

    return all_records

def compute_additional_hashes(records):
    print("\nAdditional hashes:")

    # Hash of exact file bytes
    with open("encrypted_dataset.json", "rb") as f:
        file_hash = hashlib.sha256(f.read()).hexdigest()

    # Hash of sorted records
    sorted_joined = "".join(sorted(records))
    sorted_hash = hashlib.sha256(sorted_joined.encode()).hexdigest()

    # Hash of base64-decoded bytes concatenated
    decoded_bytes = b"".join(
        base64.b64decode(record)
        for record in records
    )
    decoded_hash = hashlib.sha256(decoded_bytes).hexdigest()

    print(f"file_hash      : {file_hash}")
    print(f"sorted_joined  : {sorted_hash}")
    print(f"decoded_bytes  : {decoded_hash}")

    return {
        "file_hash": file_hash,
        "sorted_joined": sorted_hash,
        "decoded_bytes": decoded_hash
  }

def compute_hashes(records):
    print("\nCandidate hashes:")

    joined = "".join(records)
    newline_joined = "\n".join(records)
    json_compact = json.dumps(records, separators=(",", ":"))
    json_pretty = json.dumps(records, indent=2)

    hashes = {
        "joined": hashlib.sha256(joined.encode()).hexdigest(),
        "newline_joined": hashlib.sha256(newline_joined.encode()).hexdigest(),
        "json_compact": hashlib.sha256(json_compact.encode()).hexdigest(),
        "json_pretty": hashlib.sha256(json_pretty.encode()).hexdigest(),
    }

    for name, value in hashes.items():
        print(f"{name}: {value}")

    return hashes


def submit_content_hash(value):
    payload = {
        "type": "content_hash",
        "value": value,
        "notes": "Fetched all 500 encrypted records using advertised batch ranges 0-99 through 400-499 and submitted the matching SHA-256 content hash."
    }
    return post("/api/v1/submit", payload)


def check_stats():
    response = get("/api/v1/stats")
    print(json.dumps(response.json(), indent=2))


def discover_openapi():
    response = requests.get(f"{BASE_URL}/openapi.json", headers=HEADERS)
    print("OpenAPI status:", response.status_code)

    try:
        print(json.dumps(response.json(), indent=2)[:5000])
    except Exception:
        print(response.text[:5000])


    paths = [
        "/openapi.json",
        "/docs",
        "/api/v1",
        "/api/v1/health",
        "/api/v1/stats",
        "/api/v1/dataset",
        "/api/v1/dataset/meta",
        "/api/v1/dataset/metadata",
        "/api/v1/dataset/key",
        "/api/v1/dataset/decrypt",
        "/api/v1/key",
        "/api/v1/keys",
        "/api/v1/decryption-key",
        "/api/v1/decryption_key",
        "/api/v1/crypto",
        "/api/v1/crypto/key",
        "/api/v1/crypto/keys",
        "/api/v1/layer2",
        "/api/v1/layers/2",
        "/api/v1/challenge",
        "/api/v1/challenges",
        "/api/v1/transcript",
        "/api/v1/instructions",
        "/api/v1/me",
        "/api/v1/status",
        "/api/v1/time"
    ]

    for path in paths:
        try:
            res = requests.get(f"{BASE_URL}{path}", headers=HEADERS, timeout=10)
            print("\n==============================")
            print(path, res.status_code)
            print("Headers:", dict(res.headers))
            print("Body:", res.text[:2000])
        except Exception as e:
            print(path, e)

def test_possible_keys(records):
    candidates = []

    raw_api_key = API_KEY.encode()
    candidates.append(("api_key_raw", raw_api_key))
    candidates.append(("api_key_sha256", hashlib.sha256(raw_api_key).digest()))

    if API_KEY.startswith("sa_"):
        stripped = API_KEY[3:].encode()
        candidates.append(("api_key_without_sa_raw", stripped))
        candidates.append(("api_key_without_sa_sha256", hashlib.sha256(stripped).digest()))

    sample = base64.b64decode(records[0])

    for name, key in candidates:
        print("\nTrying", name, "length", len(key))

        # AES-GCM attempt: first 12 bytes nonce, last 16 bytes tag included automatically
        if len(key) in [16, 24, 32] and len(sample) > 28:
            try:
                aesgcm = AESGCM(key)
                nonce = sample[:12]
                ciphertext = sample[12:]
                plain = aesgcm.decrypt(nonce, ciphertext, None)
                print("AESGCM SUCCESS:", name, plain[:200])
            except Exception as e:
                print("AESGCM failed")

        # Fernet attempt
        try:
            fkey = base64.urlsafe_b64encode(key[:32])
            f = Fernet(fkey)
            plain = f.decrypt(records[0].encode())
            print("FERNET SUCCESS:", name, plain[:200])
        except Exception:
            print("Fernet failed")

if __name__ == "__main__":
    #check_stats()

    find_layer3_hidden_word()

    #records = fetch_dataset()
    #test_possible_keys(records)

    #hashes = compute_hashes(records)
    #extra_hashes = compute_additional_hashes(records)

    #quick_discover()

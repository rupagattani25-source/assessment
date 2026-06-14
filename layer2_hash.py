import os
import json
import time
import base64
import hashlib
import requests
from dotenv import load_dotenv

from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding


load_dotenv()

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
        print(response.text)

    response.raise_for_status()
    return response


def post(path, payload):
    url = f"{BASE_URL}{path}"
    response = requests.post(
        url,
        headers={**HEADERS, "Content-Type": "application/json"},
        json=payload
    )

    print(f"POST {path} -> {response.status_code}")
    print(response.text)

    return response


def fetch_dataset():
    all_records = []
    ranges = ["0-99", "100-199", "200-299", "300-399", "400-499"]

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


def compute_layer1_hash(records):
    decoded_bytes = b"".join(base64.b64decode(r) for r in records)
    content_hash = hashlib.sha256(decoded_bytes).hexdigest()

    print("\nLayer 1 content_hash:")
    print(content_hash)

    return content_hash


def submit_layer1(content_hash):
    payload = {
        "type": "content_hash",
        "value": content_hash,
        "notes": "Fetched all 500 records using advertised batch ranges. Base64-decoded each encrypted record and computed SHA-256 over concatenated encrypted bytes."
    }

    return post("/api/v1/submit", payload)


def get_private_key():
    response = get("/api/v1/private-key")
    key_text = response.text

    with open("private_key.pem", "w", encoding="utf-8") as f:
        f.write(key_text)

    print("Private key saved to private_key.pem")


def load_private_key():
    with open("private_key.pem", "rb") as f:
        return serialization.load_pem_private_key(
            f.read(),
            password=None
        )


def decrypt_record(record, private_key):
    encrypted = base64.b64decode(record)

    try:
        return private_key.decrypt(
            encrypted,
            padding.PKCS1v15()
        )
    except Exception:
        pass

    try:
        return private_key.decrypt(
            encrypted,
            padding.OAEP(
                mgf=padding.MGF1(hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
    except Exception:
        pass

    return private_key.decrypt(
        encrypted,
        padding.OAEP(
            mgf=padding.MGF1(hashes.SHA1()),
            algorithm=hashes.SHA1(),
            label=None
        )
    )


def decrypt_all_records(records):
    private_key = load_private_key()
    decrypted_records = []

    for idx, record in enumerate(records):
        decrypted = decrypt_record(record, private_key)
        decrypted_records.append(decrypted)

        if idx == 0:
            print("\nFirst decrypted record sample:")
            print(decrypted[:300])

    with open("decrypted_dataset.bin", "wb") as f:
        for item in decrypted_records:
            f.write(item)

    print(f"Decrypted records: {len(decrypted_records)}")

    return decrypted_records


def compute_layer2_hash(decrypted_records):
    decrypted_bytes = b"".join(decrypted_records)
    decrypted_hash = hashlib.sha256(decrypted_bytes).hexdigest()

    print("\nLayer 2 decrypted_hash:")
    print(decrypted_hash)

    return decrypted_hash


def submit_layer2(decrypted_hash):
    print("\nSubmitting Layer 2 decrypted_hash...",decrypted_hash)
    payload = {
        "type": "decrypted_hash",
        "value": decrypted_hash,
        "notes": "Decrypted all 500 records using the platform-issued private key and computed SHA-256 over concatenated decrypted bytes."
    }
    
    return post("/api/v1/submit", payload)


def save_decrypted_jsonl(decrypted_records):
    with open("decrypted_dataset.jsonl", "w", encoding="utf-8") as f:
        for item in decrypted_records:
            text = item.decode("utf-8", errors="replace")
            f.write(text + "\n")

    print("Saved decrypted records to decrypted_dataset.jsonl")


def main():
    print("Starting assessment script...")

    records = fetch_dataset()

    content_hash = compute_layer1_hash(records)

    print("\nSubmit Layer 1? Uncomment below after verifying.")
    # submit_layer1(content_hash)

    print("\nFetching private key...")
    get_private_key()

    decrypted_records = decrypt_all_records(records)

    decrypted_hash = compute_layer2_hash(decrypted_records)

    save_decrypted_jsonl(decrypted_records)

    print("\nSubmit Layer 2? Uncomment below after verifying.")
    submit_layer2(decrypted_hash)


if __name__ == "__main__":
    main()
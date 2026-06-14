import json
import re
from collections import Counter

# Load decrypted records
with open("decrypted_records.json", "r") as f:
    raw_records = json.load(f)

parsed = [json.loads(r) for r in raw_records if r]
print(f"Total records: {len(parsed)}")
print(f"Fields: {list(parsed[0].keys())}")

# ─────────────────────────────────────────────
# METHOD 1: First letter of endpoint path
# ─────────────────────────────────────────────
print("\n--- Method 1: First letter of endpoint ---")
endpoint_letters = ""
for r in parsed:
    ep = r.get("endpoint", "")
    # Get first letter after /api/v1/
    parts = ep.strip("/").split("/")
    last_part = parts[-1] if parts else ""
    if last_part:
        endpoint_letters += last_part[0]
print(f"First letter of last path segment: {endpoint_letters}")

# ─────────────────────────────────────────────
# METHOD 2: Status code pattern
# ─────────────────────────────────────────────
print("\n--- Method 2: Status codes ---")
status_codes = [r.get("status_code") for r in parsed]
print(f"Unique status codes: {sorted(set(status_codes))}")
print(f"Status distribution: {Counter(status_codes)}")

# Map status codes to letters (e.g. 200=A, 201=B etc)
status_map = {200: 'A', 201: 'B', 204: 'C', 400: 'D', 401: 'E', 403: 'F', 404: 'G', 429: 'H', 500: 'I', 503: 'J'}
status_word = "".join(status_map.get(r.get("status_code"), "?") for r in parsed)
print(f"Status mapped to letters: {status_word[:50]}")

# ─────────────────────────────────────────────
# METHOD 3: user_segment first letters - look for repeating word
# ─────────────────────────────────────────────
print("\n--- Method 3: user_segment analysis ---")
segments    = [r.get("user_segment", "") for r in parsed]
unique_segs = sorted(set(segments))
print(f"Unique user_segments: {unique_segs}")
print(f"Distribution: {Counter(segments)}")

# Map segments to letters
seg_letters = {seg: seg[0] for seg in unique_segs}
print(f"Segment->letter map: {seg_letters}")
seg_word = "".join(seg_letters.get(r.get("user_segment", ""), "?") for r in parsed)
print(f"Segment first letters: {seg_word[:100]}")

# ─────────────────────────────────────────────
# METHOD 4: endpoint last segment -> first letter
# ─────────────────────────────────────────────
print("\n--- Method 4: Unique endpoints ---")
endpoints    = [r.get("endpoint", "") for r in parsed]
unique_eps   = sorted(set(endpoints))
print(f"Unique endpoints: {unique_eps}")
print(f"Distribution: {Counter(endpoints).most_common(10)}")

# ─────────────────────────────────────────────
# METHOD 5: method sequence
# ─────────────────────────────────────────────
print("\n--- Method 5: HTTP methods ---")
methods = [r.get("method", "") for r in parsed]
print(f"Unique methods: {sorted(set(methods))}")
print(f"Distribution: {Counter(methods)}")

# ─────────────────────────────────────────────
# METHOD 6: latency_ms — look for ASCII values
# ─────────────────────────────────────────────
print("\n--- Method 6: latency_ms as ASCII ---")
latencies = [r.get("latency_ms") for r in parsed]
ascii_attempt = ""
for lat in latencies:
    if lat and 32 <= lat <= 126:
        ascii_attempt += chr(lat)
    else:
        ascii_attempt += "?"
print(f"Latency as ASCII (printable only): {ascii_attempt[:100]}")

# ─────────────────────────────────────────────
# METHOD 7: request_bytes as ASCII
# ─────────────────────────────────────────────
print("\n--- Method 7: request_bytes as ASCII ---")
req_bytes = [r.get("request_bytes") for r in parsed]
ascii_attempt2 = ""
for rb in req_bytes:
    if rb and 32 <= rb <= 126:
        ascii_attempt2 += chr(rb)
    else:
        ascii_attempt2 += "?"
print(f"Request bytes as ASCII: {ascii_attempt2[:100]}")

# ─────────────────────────────────────────────
# METHOD 8: Sort by timestamp, then first letters
# ─────────────────────────────────────────────
print("\n--- Method 8: Sorted by timestamp ---")
sorted_records = sorted(parsed, key=lambda x: x.get("timestamp", ""))
ts_endpoint_letters = "".join(r.get("endpoint","").split("/")[-1][0] for r in sorted_records if r.get("endpoint","").split("/")[-1])
print(f"Endpoint last segment first letter (time-sorted): {ts_endpoint_letters}")

ts_method_letters = "".join(r.get("method","")[0] for r in sorted_records if r.get("method"))
print(f"Method first letter (time-sorted): {ts_method_letters}")

ts_seg_letters = "".join(r.get("user_segment","")[0] for r in sorted_records if r.get("user_segment"))
print(f"Segment first letter (time-sorted): {ts_seg_letters}")

# ─────────────────────────────────────────────
# METHOD 9: Look for hidden alpha word in any field combo
# ─────────────────────────────────────────────
print("\n--- Method 9: Scanning all string fields for alpha patterns ---")
for field in ["endpoint", "method", "user_segment", "timestamp"]:
    values = [str(r.get(field, "")) for r in parsed]
    # Extract only alpha chars
    alpha_only = "".join(re.sub(r'[^a-zA-Z]', '', v) for v in values)
    print(f"Alpha from '{field}': {alpha_only[:80]}")

# ─────────────────────────────────────────────
# METHOD 10: Check if latency values spell something when sorted
# ─────────────────────────────────────────────
print("\n--- Method 10: Latency outliers ---")
latencies_sorted = sorted(latencies)
print(f"Min latency: {min(latencies)}")
print(f"Max latency: {max(latencies)}")
print(f"Mean latency: {sum(latencies)/len(latencies):.0f}")
print(f"Latency values <= 126 (possible ASCII): {[l for l in latencies if l and l <= 126]}")
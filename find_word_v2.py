import json
from collections import Counter

with open("decrypted_records.json") as f:
    records = [json.loads(r) for r in json.load(f) if r]

sorted_r = sorted(records, key=lambda x: x["timestamp"])

print("Total records:", len(records))
print()

# ── KEY INSIGHT ──────────────────────────────────────────
# "hidden ACROSS the records" = one character per record
# 500 records → 500 chars → look for repeating short word
# ─────────────────────────────────────────────────────────

# All possible per-record character extractions
sequences = {}

# 1. First char of each field
for field in ['endpoint', 'method', 'user_segment', 'timestamp']:
    key = f"first_char_{field}"
    sequences[key] = "".join(str(r.get(field,''))[0] for r in sorted_r if r.get(field))

# 2. Last char of each string field  
for field in ['endpoint', 'method', 'user_segment']:
    key = f"last_char_{field}"
    sequences[key] = "".join(str(r.get(field,''))[-1] for r in sorted_r if r.get(field))

# 3. Endpoint last path segment first char
sequences['ep_last_seg_first'] = "".join(r['endpoint'].split('/')[-1][0] for r in sorted_r)

# 4. Endpoint last path segment last char
sequences['ep_last_seg_last'] = "".join(r['endpoint'].split('/')[-1][-1] for r in sorted_r)

# 5. Status code first digit
sequences['status_first_digit'] = "".join(str(r['status_code'])[0] for r in sorted_r)

# 6. Status code last digit  
sequences['status_last_digit'] = "".join(str(r['status_code'])[-1] for r in sorted_r)

# Now check each sequence for repeating word pattern
print("="*60)
print("LOOKING FOR REPEATING WORD PATTERN IN EACH SEQUENCE")
print("="*60)

def find_repeating_word(seq, name):
    seq = seq.lower()
    # Try word lengths 3-12
    for word_len in range(3, 13):
        if len(seq) % word_len != 0:
            # Try first portion that divides evenly
            test_len = (len(seq) // word_len) * word_len
            chunk = seq[:test_len]
        else:
            chunk = seq

        # Split into chunks of word_len
        chunks = [chunk[i:i+word_len] for i in range(0, len(chunk), word_len)]
        # Check if all chunks are the same
        unique = set(chunks)
        if len(unique) == 1:
            word = chunks[0]
            if word.isalpha():
                print(f"  ✓ FOUND repeating word (len={word_len}) in {name}: '{word}'")
                return word

        # Check if most chunks repeat (allow some noise)
        most_common = Counter(chunks).most_common(1)[0]
        if most_common[1] >= len(chunks) * 0.8 and most_common[0].isalpha():
            print(f"  ~ LIKELY word (len={word_len}, {most_common[1]}/{len(chunks)}) in {name}: '{most_common[0]}'")

for name, seq in sequences.items():
    find_repeating_word(seq, name)

# ── DIRECT APPROACH ─────────────────────────────────────
print("\n" + "="*60)
print("DIRECT: CHECK EVERY SEQUENCE FOR ANY ALPHA WORD")
print("="*60)

for name, seq in sequences.items():
    alpha_only = "".join(c for c in seq.lower() if c.isalpha())
    # Check for repeating pattern
    for word_len in range(3, 13):
        chunks = [alpha_only[i:i+word_len] for i in range(0, len(alpha_only)-word_len, word_len)]
        if not chunks:
            continue
        most_common = Counter(chunks).most_common(1)[0]
        ratio = most_common[1] / len(chunks)
        if ratio >= 0.85 and most_common[0].isalpha():
            print(f"  ✓ {name} (len={word_len}, {ratio:.0%}): '{most_common[0]}'")

# ── NUMERIC FIELD ENCODING ───────────────────────────────
print("\n" + "="*60)
print("NUMERIC ENCODING: latency_ms and request_bytes mod N")
print("="*60)

latencies     = [r['latency_ms'] for r in sorted_r]
request_bytes = [r['request_bytes'] for r in sorted_r]

# Try modulo of number of unique values
for field_name, values in [("latency_ms", latencies), ("request_bytes", request_bytes)]:
    unique_count = len(set(values))
    print(f"\n{field_name}: min={min(values)}, max={max(values)}, unique={unique_count}")

    for mod in [26, 10, 52, 5]:
        chars = [chr(ord('a') + (v % mod)) if (v % mod) < 26 else '?' for v in values]
        word = "".join(chars)
        # Check for repeating pattern
        for wl in range(3, 13):
            chunks = [word[i:i+wl] for i in range(0, len(word), wl)]
            mc = Counter(chunks).most_common(1)[0]
            if mc[1]/len(chunks) >= 0.8 and mc[0].isalpha():
                print(f"  ✓ mod {mod}, wordlen {wl}: '{mc[0]}'")
        print(f"  mod {mod} first 30 chars: {word[:30]}")

# ── STATUS CODE AS WORD INDEX ────────────────────────────
print("\n" + "="*60)
print("STATUS CODE MAPPED TO ALPHABET POSITION")
print("="*60)

unique_statuses = sorted(set(r['status_code'] for r in sorted_r))
print(f"Unique statuses: {unique_statuses}")
# Map each status to a-l (12 statuses = 12 letters)
st_map = {s: chr(ord('a')+i) for i,s in enumerate(unique_statuses)}
print(f"Status->letter: {st_map}")
status_word = "".join(st_map[r['status_code']] for r in sorted_r)
print(f"Status sequence: {status_word[:60]}")

for wl in range(3, 13):
    chunks = [status_word[i:i+wl] for i in range(0, len(status_word), wl)]
    mc = Counter(chunks).most_common(1)[0]
    if mc[1]/len(chunks) >= 0.7 and mc[0].isalpha():
        print(f"  ✓ Repeating word (len={wl}): '{mc[0]}'")

# ── ENDPOINT INDEX AS LETTER ─────────────────────────────
print("\n" + "="*60)
print("ENDPOINT INDEX -> LETTER (sorted alphabetically)")
print("="*60)

unique_eps = sorted(set(r['endpoint'] for r in sorted_r))
ep_map     = {ep: chr(ord('a')+i) for i, ep in enumerate(unique_eps)}
print(f"Endpoint->letter: {ep_map}")
ep_word = "".join(ep_map[r['endpoint']] for r in sorted_r)
print(f"Endpoint sequence: {ep_word[:60]}")

for wl in range(3, 13):
    chunks = [ep_word[i:i+wl] for i in range(0, len(ep_word), wl)]
    mc = Counter(chunks).most_common(1)[0]
    if mc[1]/len(chunks) >= 0.7 and mc[0].isalpha():
        print(f"  ✓ Repeating word (len={wl}): '{mc[0]}'")

# ── SEGMENT INDEX AS LETTER ──────────────────────────────
print("\n" + "="*60)
print("SEGMENT INDEX -> LETTER (sorted alphabetically)")
print("="*60)

unique_segs = sorted(set(r['user_segment'] for r in sorted_r))
seg_map     = {s: chr(ord('a')+i) for i, s in enumerate(unique_segs)}
print(f"Segment->letter: {seg_map}")
seg_word = "".join(seg_map[r['user_segment']] for r in sorted_r)
print(f"Segment sequence: {seg_word[:60]}")

for wl in range(3, 13):
    chunks = [seg_word[i:i+wl] for i in range(0, len(seg_word), wl)]
    mc = Counter(chunks).most_common(1)[0]
    if mc[1]/len(chunks) >= 0.7 and mc[0].isalpha():
        print(f"  ✓ Repeating word (len={wl}): '{mc[0]}'")
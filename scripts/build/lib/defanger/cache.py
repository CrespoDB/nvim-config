import json, os, time
from .settings import CACHE_FILE

def load_cache():
    if os.path.exists(CACHE_FILE):
        with open(CACHE_FILE) as f:
            return json.load(f)
    return {}

def save_cache(data):
    os.makedirs(os.path.dirname(CACHE_FILE), exist_ok=True)
    with open(CACHE_FILE, "w") as f:
        json.dump(data, f, indent=2)

def is_stale(entry, max_age_hours=24):
    ts = entry.get("timestamp", 0)
    return (time.time() - ts) > max_age_hours * 3600


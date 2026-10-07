import time

import requests

from .config import USER_AGENT

_session = requests.Session()
_session.headers["User-Agent"] = USER_AGENT


def get(url, params=None, headers=None, timeout=60, retries=3, retry_on=(429, 503)):
    last = None
    for attempt in range(retries):
        r = _session.get(url, params=params, headers=headers, timeout=timeout)
        if r.status_code in retry_on and attempt < retries - 1:
            time.sleep(6 * (attempt + 1))
            last = r
            continue
        r.raise_for_status()
        return r
    last.raise_for_status()
    return last

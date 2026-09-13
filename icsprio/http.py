"""Shared HTTP session: consistent User-Agent, timeout, and retry policy
for every source module. Centralizing this means a rate limit or outage on
one source doesn't need its own bespoke retry loop.

Retries are implemented with the standard library only (exponential
backoff via `time.sleep`) rather than a third-party retry library, so
icsprio's runtime dependency list stays minimal.
"""

from __future__ import annotations

import time

import requests

from . import config


def get_session() -> requests.Session:
    session = requests.Session()
    session.headers.update({"User-Agent": config.USER_AGENT, "Accept": "application/json"})
    return session


class FetchError(RuntimeError):
    """Raised when a source cannot be fetched after retries."""


def get(session: requests.Session, url: str, **kwargs) -> requests.Response:
    """GET with exponential-backoff retry on transient network errors.

    Raises FetchError on a non-2xx response; 4xx/5xx are NOT retried, since
    retrying a bad request or an auth failure wastes the source's
    rate-limit budget without changing the outcome. Only connection and
    timeout errors are retried, up to `config.MAX_RETRIES` attempts.
    """
    kwargs.setdefault("timeout", config.REQUEST_TIMEOUT_SECONDS)
    last_exc = None
    for attempt in range(config.MAX_RETRIES):
        try:
            resp = session.get(url, **kwargs)
        except (requests.ConnectionError, requests.Timeout) as exc:
            last_exc = exc
            if attempt < config.MAX_RETRIES - 1:
                time.sleep(min(2**attempt, 20))
            continue
        if resp.status_code >= 400:
            raise FetchError(f"GET {url} -> HTTP {resp.status_code}: {resp.text[:300]}")
        return resp
    raise FetchError(f"GET {url} failed after {config.MAX_RETRIES} attempts: {last_exc}")

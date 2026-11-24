"""Advisory-only checks against the canonical public GitHub release feed."""
from datetime import datetime, timedelta, timezone
from http.client import HTTPException
import json
from queue import Empty, Queue
import re
from threading import Lock, Thread
from urllib.error import HTTPError, URLError
from urllib.request import HTTPRedirectHandler, Request, build_opener

from . import __version__
from .sddc_install import InstallError, _load, _locked_state, _write

API = "https://api.github.com/repos/kiefer413/vcf-cert-renewer/releases"
WEB = "https://github.com/kiefer413/vcf-cert-renewer/releases/tag/"
VERSION = re.compile(r"v?(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)"
                     r"(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?"
                     r"(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?", re.ASCII)
WORKER = Lock()


class CheckError(ValueError):
    pass


def version(value):
    match = VERSION.fullmatch(value) if isinstance(value, str) and len(value) <= 128 else None
    if not match:
        raise CheckError("INVALID_VERSION")
    suffix = (match[4] or "").split(".") if match[4] else ()
    if any(p.isdecimal() and len(p) > 1 and p.startswith("0") for p in suffix):
        raise CheckError("INVALID_VERSION")
    parts = tuple((0, int(p)) if p.isdecimal() else (1, p) for p in suffix)
    return tuple(map(int, match.group(1, 2, 3))), not suffix, parts


def options(env):
    def flag(key, default):
        val = env.get(key, default).lower()
        if val not in {"true", "false"}:
            raise CheckError("INVALID_" + key)
        return val == "true"

    enabled = flag("UPDATE_CHECK_ENABLED", "true")
    if not enabled:
        return enabled, 24, 10, False

    def number(key, default, lo, hi):
        try:
            value = int(env.get(key, default))
        except (TypeError, ValueError):
            raise CheckError("INVALID_" + key) from None
        if not lo <= value <= hi:
            raise CheckError("INVALID_" + key)
        return value

    return (enabled, number("UPDATE_CHECK_INTERVAL_HOURS", 24, 1, 720),
            number("UPDATE_CHECK_TIMEOUT_SECONDS", 10, 1, 30),
            flag("UPDATE_CHECK_INCLUDE_PRERELEASE", "false"))


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _release(record, prerelease):
    if (not isinstance(record, dict) or type(record.get("draft")) is not bool
            or type(record.get("prerelease")) is not bool):
        raise CheckError("INVALID_RELEASE_RESPONSE")
    if record["draft"] or (record["prerelease"] and not prerelease):
        return None
    tag = record.get("tag_name")
    try:
        key = version(tag)
    except CheckError:
        return None
    if not prerelease and not key[1]:
        return None
    published = record.get("published_at")
    if not isinstance(published, str):
        raise CheckError("INVALID_RELEASE_RESPONSE")
    try:
        stamp = datetime.fromisoformat(published)
        if stamp.utcoffset() is None:
            raise ValueError
    except ValueError:
        raise CheckError("INVALID_RELEASE_RESPONSE") from None
    return {"latest_version": tag.removeprefix("v"), "release_url": WEB + tag,
            "published_at": stamp.astimezone(timezone.utc).isoformat()}


def fetch(timeout, prerelease, etag):
    headers = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28",
               "User-Agent": "vcf-cert-renewer/" + __version__}
    if etag and not prerelease:
        headers["If-None-Match"] = etag
    candidates = []
    opener = build_opener(NoRedirect())
    for page in range(1, 6):
        url = f"{API}?per_page=100&page={page}" if prerelease else API + "/latest"
        try:
            with opener.open(Request(url, headers=headers), timeout=timeout) as response:
                raw = response.read(1024 * 1024 + 1)
                if len(raw) > 1024 * 1024:
                    raise CheckError("RESPONSE_TOO_LARGE")
                tag = response.headers.get("ETag", "")
                next_page = 'rel="next"' in response.headers.get("Link", "")
        except HTTPError as exc:
            with exc:
                if exc.code == 304 and etag and not prerelease:
                    return None, etag
                if exc.code == 429 or exc.code == 403 and exc.headers.get("X-RateLimit-Remaining") == "0":
                    raise CheckError("RATE_LIMITED") from None
                raise CheckError(f"HTTP_{exc.code}") from None
        except (OSError, URLError, HTTPException):
            raise CheckError("NETWORK_OR_TLS_ERROR") from None
        try:
            data = json.loads(raw)
        except (ValueError, RecursionError):
            raise CheckError("INVALID_JSON") from None
        if prerelease and not isinstance(data, list):
            raise CheckError("INVALID_RELEASE_RESPONSE")
        for record in data if prerelease else [data]:
            release = _release(record, prerelease)
            if release:
                candidates.append(release)
        if not prerelease or not next_page:
            if not candidates:
                raise CheckError("NO_ELIGIBLE_RELEASE")
            safe_etag = tag if re.fullmatch(r'(?:W/)?"[!-~]{1,200}"', tag) else None
            return max(candidates, key=lambda item: version(item["latest_version"])), safe_etag
    raise CheckError("RELEASE_PAGE_LIMIT")


def _bounded_fetch(timeout, prerelease, etag):
    """Bound the whole request, including DNS, with at most one outstanding worker."""
    if not WORKER.acquire(blocking=False):
        raise CheckError("REQUEST_STILL_RUNNING")
    result = Queue(maxsize=1)

    def read():
        try:
            result.put(fetch(timeout, prerelease, etag))
        except CheckError as exc:
            result.put(exc)
        except Exception:
            result.put(CheckError("REQUEST_FAILED"))
        finally:
            WORKER.release()

    Thread(target=read, daemon=True).start()
    try:
        value = result.get(timeout=timeout)
    except Empty:
        raise CheckError("REQUEST_TIMEOUT") from None
    if isinstance(value, CheckError):
        raise value
    return value


def _validate(value):
    if not isinstance(value, dict) or value.get("schema") != 1:
        raise ValueError
    if value.get("latest_version"):
        version(value["latest_version"])


def _read(output):
    import os
    directory = output / ".software-update"
    try:
        fd = os.open(directory, os.O_DIRECTORY | os.O_NOFOLLOW)
    except FileNotFoundError:
        return {}
    try:
        from .sddc_install import _check_private
        import stat
        _check_private(fd, 0o700, stat.S_ISDIR)
        return _load(fd, _validate)
    finally:
        os.close(fd)


def _comparison(latest):
    if not latest:
        return "NOT_CHECKED"
    installed, available = version(__version__), version(latest)
    return ("UPDATE_AVAILABLE" if installed < available else
            "INSTALLED_VERSION_NEWER" if installed > available else "UP_TO_DATE")


def status(output, env):
    try:
        enabled, _, _, prerelease = options(env)
    except CheckError as exc:
        enabled, prerelease = True, False
        state = {"last_outcome": "CHECK_FAILED", "error_code": str(exc)}
    else:
        try:
            state = _read(output)
        except (OSError, InstallError, ValueError):
            state = {"last_outcome": "CHECK_FAILED", "error_code": "UPDATE_STATE_UNAVAILABLE"}
    latest = state.get("latest_version") if state.get("prerelease", False) == prerelease else None
    comparison = _comparison(latest)
    failed = state.get("last_outcome") == "CHECK_FAILED"
    return {"enabled": enabled, "installed_version": __version__, "latest_version": latest,
            "update_available": enabled and comparison == "UPDATE_AVAILABLE",
            "status": "DISABLED" if not enabled else "CHECK_FAILED" if failed else comparison,
            "cached_status": comparison, "check_status": "DISABLED" if not enabled else
            "FAILED" if failed else "SUCCESS" if latest else "NOT_CHECKED",
            "release_channel": "prerelease" if prerelease else "stable",
            "last_check": state.get("last_check"),
            "last_successful_check": state.get("last_successful_check") if latest else None,
            "release_url": state.get("release_url") if latest else None,
            "published_at": state.get("published_at") if latest else None,
            "cache_may_be_stale": bool(latest and (failed or not enabled)),
            "consecutive_failures": state.get("consecutive_failures", 0),
            "error_code": state.get("error_code") if failed else None,
            "automatic_installation": False}


def check(output, events, env, *, force=False):
    error = None
    try:
        enabled, hours, timeout, prerelease = options(env)
    except CheckError as exc:
        enabled, hours, timeout, prerelease = True, 24, 10, False
        error = exc
    if not enabled:
        return
    output.mkdir(parents=True, exist_ok=True)
    with _locked_state(output, ".software-update") as fd:
        prior = _load(fd, _validate)
        current = datetime.now(timezone.utc)
        previous = prior.get("last_check")
        same_channel = prior.get("prerelease", False) == prerelease
        if (not force and same_channel and previous
                and timedelta(0) <= current - datetime.fromisoformat(previous) < timedelta(hours=hours)):
            return
        stamp = current.isoformat()
        state = dict(prior, schema=1, last_check=stamp)
        try:
            if error:
                raise error
            metadata, etag = _bounded_fetch(timeout, prerelease, prior.get("etag") if same_channel else None)
            if metadata is not None:
                state.update(metadata)
            state.update(prerelease=prerelease, etag=etag, last_successful_check=stamp,
                         last_outcome="SUCCESS", consecutive_failures=0)
            state.pop("error_code", None)
        except CheckError as exc:
            code = str(exc)
            state.update(last_outcome="CHECK_FAILED", error_code=code,
                         consecutive_failures=prior.get("consecutive_failures", 0) + 1)
            _write(fd, state)
            if prior.get("error_code") != code:
                events.emit("VCF-6020", outcome="CHECK_FAILED", error_code=code)
            return
        comparison = _comparison(state["latest_version"])
        fields = {key: state[key] for key in ("latest_version", "release_url")}
        fields.update(installed_version=__version__, outcome=comparison)
        recovered = prior.get("last_outcome") == "CHECK_FAILED"
        notify = (comparison == "UPDATE_AVAILABLE"
                  and prior.get("last_notified_version") != state["latest_version"])
        if notify:
            state["last_notified_version"] = state["latest_version"]
        state["last_comparison"] = comparison
        _write(fd, state)
        if recovered:
            events.emit("VCF-6030", **fields)
        if notify:
            events.emit("VCF-6000", **fields)
        elif comparison == "UP_TO_DATE" and prior.get("last_comparison") != comparison:
            events.emit("VCF-6010", **fields)


def advisory(output, events, env, *, force=False):
    try:
        check(output, events, env, force=force)
    except (OSError, InstallError, ValueError, KeyError, TypeError):
        if force:
            events.emit("VCF-6020", outcome="CHECK_FAILED", error_code="UPDATE_STATE_UNAVAILABLE")
        return False
    return True

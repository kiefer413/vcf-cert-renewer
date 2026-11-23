"""Standalone read-only SDDC parent task gate. No renewal entry point."""
from dataclasses import dataclass
import re
from uuid import UUID

ACTIVE = frozenset("PENDING IN_PROGRESS QUEUED RUNNING STARTED".split())
TERMINAL = frozenset(
    "SUCCESSFUL SUCCESS COMPLETED FAILED CANCELLED CANCELED "
    "COMPLETED_WITH_WARNING SKIPPED TIMED_OUT".split()
)


@dataclass(frozen=True)
class Stop(Exception):
    reason: str
    page: int
    task_id: str = "UNAVAILABLE"
    status: str = "UNAVAILABLE"

    def __str__(self):
        return (f"STOP reason={self.reason} page={self.page} "
                f"task_id={self.task_id} status={self.status}")


def task_record(record, page):
    if not isinstance(record, dict):
        raise Stop("MALFORMED_TASK", page)
    raw = record.get("status")
    status = re.sub(r"[\s_-]+", "_", raw.strip().upper()) if isinstance(raw, str) else ""
    known = status in ACTIVE | TERMINAL
    safe_status = status if known else "MISSING" if raw is None or raw == "" else "UNKNOWN"
    try:
        task_id = str(UUID(record["id"]))
    except (KeyError, ValueError, TypeError, AttributeError):
        raise Stop("INVALID_TASK_ID", page, status=safe_status) from None
    if status not in TERMINAL:
        reason = ("ACTIVE_TASK" if status in ACTIVE else
                  "MISSING_STATUS" if raw is None or isinstance(raw, str) and not raw.strip() else
                  "INVALID_STATUS_TYPE" if not isinstance(raw, str) else "UNKNOWN_STATUS")
        raise Stop(reason, page, task_id, safe_status)
    return task_id, status


def check_tasks(fetch, page_size=100, max_pages=100):
    """Fetch documented one-based pages and recheck the first-page anchor."""
    def read(page):
        try:
            payload = fetch(page, page_size)
        except Exception:
            raise Stop("REQUEST_OR_JSON_FAILURE", page) from None
        if not isinstance(payload, dict) or not isinstance(payload.get("elements"), list):
            raise Stop("MALFORMED_COLLECTION", page)
        meta = payload.get("pageMetadata")
        names = "pageNumber", "pageSize", "totalPages", "totalElements"
        if not isinstance(meta, dict) or any(type(meta.get(k)) is not int for k in names):
            raise Stop("MALFORMED_METADATA", page)
        number, size, pages, total = (meta[k] for k in names)
        if number != page or size != page_size or total < 0:
            raise Stop("UNEXPECTED_PAGE_METADATA", page)
        if pages != (total + size - 1) // size or pages > max_pages:
            raise Stop("INVALID_PAGE_TOTAL", page)
        records = payload["elements"]
        if len(records) != max(0, min(size, total - (page - 1) * size)):
            raise Stop("UNEXPECTED_RECORD_COUNT", page)
        return (size, pages, total), records

    expected, first = read(1)
    seen = set()
    anchor = None
    for page in range(1, max(1, expected[1]) + 1):
        meta, records = (expected, first) if page == 1 else read(page)
        if meta != expected:
            raise Stop("COLLECTION_CHANGED", page)
        normalized = []
        for record in records:
            task_id, status = task_record(record, page)
            if task_id in seen:
                raise Stop("DUPLICATE_TASK", page, task_id, status)
            seen.add(task_id)
            normalized.append((task_id, status))
        if page == 1:
            anchor = normalized
    meta, records = read(1)
    if meta != expected or [task_record(r, 1) for r in records] != anchor:
        raise Stop("FIRST_PAGE_CHANGED", 1)
    return len(seen)

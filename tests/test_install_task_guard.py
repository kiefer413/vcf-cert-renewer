import unittest
from uuid import UUID
from vcf_cert_renewer.task_guard import Stop, check_tasks


def task(n=1, status="Successful"):
    return {"id": str(UUID(int=n)), "status": status}


def page(records, number=1, total=None):
    total = len(records) if total is None else total
    return {"elements": records, "pageMetadata": {
        "pageNumber": number, "pageSize": 2, "totalPages": (total + 1) // 2,
        "totalElements": total}}


class GateTests(unittest.TestCase):
    def stop(self, fetch, reason):
        with self.assertRaises(Stop) as got:
            check_tasks(fetch, page_size=2)
        self.assertEqual(got.exception.reason, reason)
        return got.exception

    def test_original_assertion(self):
        old = lambda status: str(status).upper().replace(" ", "_") not in {
            "PENDING", "IN_PROGRESS", "RUNNING", "QUEUED", "STARTED"}
        self.assertFalse(old("In Progress"))
        self.assertTrue(old(None))
        self.assertTrue(old(" In  Progress "))

    def test_active(self):
        for status in ("In Progress", " In  Progress ", "Queued", "pending", "STARTED"):
            with self.subTest(status=status):
                error = self.stop(lambda *_: page([task(status=status)]), "ACTIVE_TASK")
                self.assertEqual(error.task_id, task()["id"])

    def test_terminal_and_multiple_pages(self):
        pages = {1: page([task(), task(2, "Timed Out")], total=3),
                 2: page([task(3, "Completed with warning")], number=2, total=3)}
        self.assertEqual(check_tasks(lambda p, _: pages[p], page_size=2), 3)

    def test_empty(self):
        self.assertEqual(check_tasks(lambda *_: page([]), page_size=2), 0)

    def test_bad_status(self):
        for status, reason in ((None,"MISSING_STATUS"), (42,"INVALID_STATUS_TYPE"),
                               ("credential=not-for-output","UNKNOWN_STATUS")):
            with self.subTest(reason=reason):
                error = self.stop(lambda *_: page([task(status=status)]), reason)
                self.assertNotIn("credential", str(error))

    def test_malformed(self):
        for payload, reason in ((None,"MALFORMED_COLLECTION"), ({"elements":[]},"MALFORMED_METADATA"),
                                (page([None]),"MALFORMED_TASK"), (page([{"id":"unsafe"}]),"INVALID_TASK_ID"),
                                (page([],total=3),"UNEXPECTED_RECORD_COUNT"),
                                (page([],number=2),"UNEXPECTED_PAGE_METADATA")):
            with self.subTest(reason=reason):
                self.stop(lambda *_: payload, reason)

    def test_duplicate(self):
        self.stop(lambda *_: page([task(),task()]), "DUPLICATE_TASK")

    def test_collection_change(self):
        self.stop(lambda p,_: page([task(),task(2)],total=3) if p==1
                  else page([task(3),task(4)],number=2,total=4), "COLLECTION_CHANGED")

    def test_anchor_change(self):
        snapshots = iter((page([task()]),page([task(2)])))
        self.stop(lambda *_: next(snapshots), "FIRST_PAGE_CHANGED")

    def test_request_failure(self):
        def fail(*_):
            raise RuntimeError("secret")
        self.assertNotIn("secret", str(self.stop(fail, "REQUEST_OR_JSON_FAILURE")))


if __name__ == "__main__":
    unittest.main()

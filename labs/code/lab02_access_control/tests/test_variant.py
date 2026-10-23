from datetime import datetime

import pytest

from accesscontrol.monitor import Permission, ReferenceMonitor
from mydetector import VariantDetector
from mypolicy import VariantPolicy, make_policy

READ = Permission.READ
WRITE = Permission.WRITE
DELETE = Permission.DELETE


def can(user, doc, action, hour=10, sod=True):
    return make_policy(sod=sod, hour=hour).evaluate(user, doc, action).allowed


class Journal:
    def __init__(self, *rows):
        self.rows = []
        for hour, user, doc in rows:
            time = datetime(2026, 10, 20, hour, 0).timestamp()
            self.rows.append({"ts": time, "subject": user, "object": doc,
                              "action": "READ", "allowed": True, "reason": ""})

    def entries(self):
        return self.rows


def test_grant():
    policy = VariantPolicy()
    policy.grant("olena", "rep03", READ)
    assert policy.evaluate("olena", "rep03", READ).allowed
    assert not policy.evaluate("olena", "rep03", WRITE).allowed


def test_attribute_rules():
    assert can("olena", "rep03", READ)
    assert can("olena", "rep02", WRITE)
    assert not can("olena", "rep03", WRITE)


def test_default_deny():
    assert not can("iryna", "rep03", READ)
    assert not can("stranger", "rep03", READ)


def test_conflicting_roles_deny_access():
    assert can("mykola", "rep10", READ, sod=False)
    assert not can("mykola", "rep10", READ)


def test_conflicting_role_cannot_be_added():
    policy = make_policy()
    with pytest.raises(ValueError):
        policy.assign_role("oksana", "auditor")


def test_time_matters():
    assert can("sofia", "rep14", READ, hour=10)
    assert not can("sofia", "rep14", READ, hour=22)


def test_every_request_is_logged():
    monitor = ReferenceMonitor(make_policy(hour=10))
    monitor.check("olena", "rep03", READ)
    monitor.check("petro", "rep10", READ)
    monitor.check("oksana", "rep18", DELETE)
    assert len(monitor.audit.entries()) == 3


def test_enforce_stops_denied_action():
    monitor = ReferenceMonitor(make_policy(hour=10))
    with pytest.raises(PermissionError):
        monitor.enforce("andriy", "rep17", DELETE)


def test_night_access_alert():
    detector = VariantDetector()
    assert len(detector.scan(Journal((23, "petro", "rep05")))) == 1
    assert detector.scan(Journal((10, "olena", "rep05"))) == []


def test_series_alert():
    detector = VariantDetector(min_series=4)
    five = Journal(*[(13, "andriy", f"rep{n}") for n in range(16, 21)])
    three = Journal(*[(13, "olena", f"rep0{n}") for n in range(1, 4)])
    assert len(detector.scan(five)) == 1
    assert detector.scan(three) == []


def test_both_anomalies():
    rows = [(2, "petro", "rep11")] + [(13, "andriy", f"rep{n}") for n in range(16, 21)]
    assert len(VariantDetector().scan(Journal(*rows))) == 2
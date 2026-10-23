from datetime import datetime

from mydetector import VariantDetector


class FakeLog:
    def __init__(self, rows):
        self.rows = [
            {"ts": datetime(2026, 10, 20, hour, 15).timestamp(), "subject": user,
             "object": doc, "action": "READ", "allowed": allowed, "reason": ""}
            for hour, user, doc, allowed in rows
        ]

    def entries(self):
        return self.rows


WORK = [
    (9,  "olena", "rep01", True),
    (10, "olena", "rep02", True),
    (11, "olena", "rep03", True),
    (14, "taras", "rep07", True),
    (16, "iryna", "rep12", True),
    (19, "sofia", "rep20", True),
]

NIGHT = [
    (23, "petro", "rep05", True),
    (2,  "petro", "rep11", False),
]

SCAN = [
    (13, "andriy", "rep16", True),
    (13, "andriy", "rep17", True),
    (13, "andriy", "rep18", False),
    (13, "andriy", "rep19", True),
    (13, "andriy", "rep20", True),
]

scenarios = [
    ("звичайна робота",       WORK,                0),
    ("нічні звернення",       WORK + NIGHT,        1),
    ("перебір документів",    WORK + SCAN,         1),
    ("обидві аномалії разом", WORK + NIGHT + SCAN, 2),
]

detector = VariantDetector(work_from=8, work_to=20, min_series=4)

print(f"вікно {detector.work_from:02d}:00–{detector.work_to:02d}:00, "
      f"поріг серії {detector.min_series}")


for name, rows, expected in scenarios:
    alerts = detector.scan(FakeLog(rows))
    verdict = "OK" if len(alerts) == expected else "ПОМИЛКА"
    print(f"[{verdict}] {name}: очікувалось {expected}, знайдено {len(alerts)}")
    for alert in alerts:
        print(f"       {alert}")


from datetime import datetime

from accesscontrol.monitor import AnomalyDetector


def doc_number(name):
    digits = "".join(ch for ch in name if ch.isdigit())
    return int(digits) if digits else None


class VariantDetector(AnomalyDetector):
    def __init__(self, work_from=8, work_to=20, min_series=4):
        self.work_from = work_from
        self.work_to = work_to
        self.min_series = min_series

    def scan(self, log):
        records = log.entries()
        alerts = []
        alerts += self.check_time(records)
        alerts += self.check_series(records)
        return alerts

    def check_time(self, records):
        night = {}
        for rec in records:
            hour = datetime.fromtimestamp(rec["ts"]).hour
            if hour < self.work_from or hour >= self.work_to:
                user = rec["subject"]
                night[user] = night.get(user, 0) + 1

        alerts = []
        for user, total in night.items():
            alerts.append(f"А2 (поза робочим часом): {user}, звернень: {total}")
        return alerts

    def check_series(self, records):
        visited = {}
        for rec in records:
            number = doc_number(rec["object"])
            if number is not None:
                visited.setdefault(rec["subject"], set()).add(number)

        alerts = []
        for user, numbers in visited.items():
            numbers = sorted(numbers)
            longest = length = 1
            for i in range(1, len(numbers)):
                if numbers[i] == numbers[i - 1] + 1:
                    length += 1
                else:
                    length = 1
                longest = max(longest, length)
            if longest >= self.min_series:
                alerts.append(f"А3 (перебір документів): {user}, номерів підряд: {longest}")
        return alerts
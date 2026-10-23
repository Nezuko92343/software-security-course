import inspect
from datetime import datetime

from accesscontrol.monitor import Permission, ReferenceMonitor
from mypolicy import VariantPolicy, make_policy

READ = Permission.READ
WRITE = Permission.WRITE
DELETE = Permission.DELETE

policy = make_policy(hour=10)
monitor = ReferenceMonitor(policy)

requests = [
    ("check",   "olena",  READ,   "rep03"),
    ("check",   "olena",  WRITE,  "rep03"),
    ("check",   "taras",  READ,   "rep03"),
    ("check",   "petro",  READ,   "rep10"),
    ("check",   "mykola", READ,   "rep10"),
    ("check",   "oksana", DELETE, "rep18"),
    ("enforce", "iryna",  WRITE,  "rep10"),
    ("enforce", "andriy", DELETE, "rep17"),
]

line = "-" * 60

print("Запити до монітора\n")
print(f"  {'#':<3}{'метод':<9}{'хто':<8}{'дія':<8}{'документ':<10}рішення")

for number, (method, user, action, doc) in enumerate(requests, 1):
    if method == "check":
        result = "дозвіл" if monitor.check(user, doc, action).allowed else "відмова"
    else:
        try:
            monitor.enforce(user, doc, action)
            result = "дозвіл"
        except PermissionError:
            result = "відмова (PermissionError)"
    print(f"  {number:<3}{method:<9}{user:<8}{action.name:<8}{doc:<10}{result}")

records = len(monitor.audit.entries())
policy.evaluate("olena", "rep01", READ)
records_after = len(monitor.audit.entries())
size = len(inspect.getsource(VariantPolicy.evaluate).splitlines())

print(line)
print("Властивості диспетчера\n")
print(f"  Повне посередництво : {len(requests)} запитів = {records} записів журналу"
      f" -> {'виконано' if records == len(requests) else 'ПОРУШЕНО'}")
print(f"  Обхід монітора      : прямий evaluate не записано ({records_after} записів)"
      f" -> видно за журналом")
print(f"  Верифіковність      : evaluate має {size} рядків -> легко перевірити")
print("  Захищеність         : дані політики приватні (_subjects, _objects, _rules)")

print(line)
print("Реєстраційний журнал\n")
print(f"  {'час':<10}{'хто':<8}{'дія':<8}{'документ':<10}{'рішення':<9}причина")
for entry in monitor.audit.entries():
    time = datetime.fromtimestamp(entry["ts"]).strftime("%H:%M:%S")
    result = "дозвіл" if entry["allowed"] else "відмова"
    print(f"  {time:<10}{entry['subject']:<8}{entry['action']:<8}"
          f"{entry['object']:<10}{result:<9}{entry['reason']}")
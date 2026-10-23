from accesscontrol.monitor import Permission
from mypolicy import USER_NAMES, DOC_NAMES, make_policy

READ = Permission.READ
WRITE = Permission.WRITE
DELETE = Permission.DELETE

policy = make_policy(hour=10)                
policy_no_sod = make_policy(sod=False, hour=10)  


def answer(pol, user, doc, action):
    return "ТАК" if pol.evaluate(user, doc, action).allowed else "НІ"


checks = [
    ("olena",  "rep03", READ,   "ТАК"),
    ("olena",  "rep02", WRITE,  "ТАК"),
    ("olena",  "rep03", WRITE,  "НІ"),
    ("taras",  "rep03", READ,   "ТАК"),
    ("taras",  "rep02", WRITE,  "НІ"),
    ("petro",  "rep05", READ,   "ТАК"),
    ("petro",  "rep10", READ,   "НІ"),
    ("petro",  "rep01", READ,   "ТАК"),
    ("iryna",  "rep03", READ,   "НІ"),
    ("mykola", "rep10", READ,   "НІ"),
    ("mykola", "rep10", WRITE,  "НІ"),
    ("oksana", "rep18", DELETE, "ТАК"),
    ("andriy", "rep17", DELETE, "НІ"),
    ("sofia",  "rep14", READ,   "ТАК"),
    ("sofia",  "rep14", WRITE,  "НІ"),
]

print("КРОК 3. Перевірка заповненої політики")
print(f"Користувачів: {len(USER_NAMES)}, документів: {len(DOC_NAMES)}\n")

print("1) Очікувані та фактичні рішення (час 10:00)")
passed = 0
for user, doc, action, expected in checks:
    decision = policy.evaluate(user, doc, action)
    actual = "ТАК" if decision.allowed else "НІ"
    if actual == expected:
        passed += 1
        mark = "OK"
    else:
        mark = "НЕ ЗБІГАЄТЬСЯ"
    print(f"   {user} -> {doc} [{action.name}]: очікувано {expected}, отримано {actual} — {mark}")
    print(f"      причина: {decision.reason}")
print(f"   Разом: {passed} із {len(checks)} рішень збіглися\n")

print("2) Вплив розділення обов'язків (D4)")
for user, doc, action in [("mykola", "rep10", READ), ("mykola", "rep10", WRITE)]:
    before = answer(policy_no_sod, user, doc, action)
    after = answer(policy, user, doc, action)
    print(f"   {user} -> {doc} [{action.name}]: без D4 — {before}, з D4 — {after}")
print()

print("3) Вплив часу (атрибут середовища)")
policy_night = make_policy(hour=22)
print(f"   sofia -> rep14 [READ] о 10:00: {answer(policy, 'sofia', 'rep14', READ)}")
print(f"   sofia -> rep14 [READ] о 22:00: {answer(policy_night, 'sofia', 'rep14', READ)}\n")

print("4) Спроба видати oksana роль auditor")
try:
    policy.assign_role("oksana", "auditor")
    print("   роль видано — це помилка!")
except ValueError as error:
    print(f"   відмовлено: {error}")
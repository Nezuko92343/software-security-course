from accesscontrol.monitor import Permission
from mypolicy import VariantPolicy

p = VariantPolicy()

p.grant("olena", "rep03", Permission.READ)

p.add_subject("taras", roles=("editor",), dept="accounting")
p.add_object("rep07", dept="accounting")
p.add_rule("свій відділ — читання", Permission.READ,
           lambda s, o, env: s.get("dept") == o.get("dept"))

p.add_conflict("editor", "reviewer")


def show(title, subject, obj, action):
    d = p.evaluate(subject, obj, action)
    result = "ТАК" if d.allowed else "НІ"
    print(f"{title}")
    print(f"   запит: {subject} -> {obj}, дія {action.name}")
    print(f"   доступ: {result} ({d.reason})\n")


show("Тест 1. Право, надане явно", "olena", "rep03", Permission.READ)
show("Тест 2. Право, яке не надавали", "olena", "rep03", Permission.WRITE)
show("Тест 3. Право за атрибутами (ABAC)", "taras", "rep07", Permission.READ)
show("Тест 4. Невідомий суб'єкт", "petro", "rep07", Permission.READ)

print("Тест 5. Призначення несумісної ролі")
try:
    p.assign_role("taras", "reviewer")
    print("   результат: роль призначено (ПОМИЛКА!)")
except ValueError as e:
    print(f"   результат: заблоковано ({e})")
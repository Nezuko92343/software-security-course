from accesscontrol.monitor import Permission, subjects_with_access
from mypolicy import DOC_NAMES, USER_NAMES, make_policy


def objects_accessible_by(policy, subject, objects, action):
    return [o for o in objects if policy.evaluate(subject, o, action).allowed]


rules = make_policy(hour=10)
READ = Permission.READ
WRITE = Permission.WRITE

print("Хто відкриває документ?")
for doc, action in [("rep03", READ), ("rep10", READ), ("rep18", WRITE)]:
    who = subjects_with_access(rules, USER_NAMES, doc, action)
    print(f"  [хто] {doc} / {action.name:<5} -> {', '.join(who) if who else 'ніхто'}")

print("\nЩо відкриває користувач?")
for user, action in [("olena", READ), ("petro", READ), ("mykola", READ), ("oksana", WRITE)]:
    what = objects_accessible_by(rules, user, DOC_NAMES, action)
    print(f"  [що]  {user} / {action.name:<5} -> ({len(what)}) {', '.join(what) if what else 'нічого'}")

print("\nЧи збігаються відповіді?")
for action in (READ, WRITE):
    from_who = set()
    for doc in DOC_NAMES:
        for user in subjects_with_access(rules, USER_NAMES, doc, action):
            from_who.add((user, doc))

    from_what = set()
    for user in USER_NAMES:
        for doc in objects_accessible_by(rules, user, DOC_NAMES, action):
            from_what.add((user, doc))

    result = "так" if from_who == from_what else "НІ"
    print(f"  {action.name:<5}: дозволених пар {len(from_who)} і {len(from_what)} -> збіг: {result}")
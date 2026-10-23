#Step 2

from datetime import datetime
from accesscontrol.monitor import Decision, Permission, Policy


class VariantPolicy(Policy):

    def __init__(self):
        self.grants = {}     
        self._subjects = {}    
        self._objects = {}     
        self._rules = []       
        self._conflicts = []   

    def add_subject(self, name, roles=(), **attrs):
        self._subjects[name] = {"roles": set(), **attrs}
        for role in roles:
            self.assign_role(name, role)

    def add_object(self, name, **attrs):
        self._objects[name] = attrs

    def add_rule(self, name, perm, condition):
       
        self._rules.append((name, perm, condition))

    def grant(self, who, obj, perm):
        key = (who, obj)
        self.grants[key] = self.grants.get(key, Permission.NONE) | perm


    def add_conflict(self, role1, role2):
        self._conflicts.append((role1, role2))

    def find_conflict(self, roles):
        for role1, role2 in self._conflicts:
            if role1 in roles and role2 in roles:
                return role1, role2
        return None

    def assign_role(self, subject, role):
        roles = self._subjects[subject]["roles"]
        if self.find_conflict(roles | {role}):
            raise ValueError(f"не можна призначити {subject} роль {role}: конфлікт ролей")
        roles.add(role)


    def current_hour(self):
        return datetime.now().hour

    def evaluate(self, subject, obj, action):
        s = self._subjects.get(subject, {})
        o = self._objects.get(obj, {})

        conflict = self.find_conflict(s.get("roles", set()))
        if conflict:
            return Decision(False, f"відмова: несумісні ролі {conflict[0]} і {conflict[1]}")

        env = {"hour": self.current_hour()}
        effective = self.grants.get((subject, obj), Permission.NONE)
        used = []
        if effective:
            used.append("явне надання")

        if subject in self._subjects and obj in self._objects:
            for name, perm, condition in self._rules:
                if condition(s, o, env):
                    effective |= perm
                    used.append(name)

        if action & effective == action:
            return Decision(True, "дозволено: " + ", ".join(used))

        return Decision(False, "відмова: немає дозволу")


#Step 3
USERS = {
    "olena":  ("accounting", 3, ["editor"]),
    "taras":  ("accounting", 2, ["reviewer"]),
    "petro":  ("hr",         1, ["employee"]),
    "iryna":  ("hr",         3, ["editor"]),
    "mykola": ("hr",         2, ["editor", "reviewer"]),
    "oksana": ("it",         3, ["admin"]),
    "andriy": ("it",         2, ["employee"]),
    "sofia":  ("audit",      3, ["auditor"]),
}
 
DOCUMENTS = {
    "rep01": ("accounting", 1), "rep02": ("accounting", 2),
    "rep03": ("accounting", 3), "rep04": ("accounting", 2),
    "rep05": ("accounting", 3), "rep06": ("accounting", 1),
    "rep07": ("accounting", 2), "rep08": ("accounting", 3),
    "rep09": ("hr", 1), "rep10": ("hr", 2), "rep11": ("hr", 3),
    "rep12": ("hr", 2), "rep13": ("hr", 3), "rep14": ("hr", 2),
    "rep15": ("hr", 1),
    "rep16": ("it", 1), "rep17": ("it", 2), "rep18": ("it", 3),
    "rep19": ("it", 2), "rep20": ("it", 2), "rep21": ("it", 3),
    "rep22": ("it", 1),
}
 
INCOMPATIBLE_ROLES = [("editor", "reviewer"), ("admin", "auditor")]
 
USER_NAMES = list(USERS)
DOC_NAMES = list(DOCUMENTS)
 
 
def rule_open_doc(user, doc, ctx):
    return doc.get("level") == 1
 
 
def rule_by_clearance(user, doc, ctx):
    return user.get("dept") == doc.get("dept") and user.get("clearance", 0) >= doc.get("level", 99)
 
 
def rule_reviewer(user, doc, ctx):
    return "reviewer" in user.get("roles", set()) and user.get("dept") == doc.get("dept")
 
 
def rule_editor(user, doc, ctx):
    return "editor" in user.get("roles", set()) and user.get("dept") == doc.get("dept") and doc.get("level", 99) <= 2
 
 
def rule_auditor(user, doc, ctx):
    return "auditor" in user.get("roles", set()) and 8 <= ctx["hour"] < 20
 
 
def rule_admin(user, doc, ctx):
    return "admin" in user.get("roles", set()) and doc.get("dept") == "it"
 
 
RULES = [
    ("документ рівня 1 відкритий для всіх",          Permission.READ,  rule_open_doc),
    ("читання в межах відділу за рівнем допуску",    Permission.READ,  rule_by_clearance),
    ("рецензент: читання всіх документів відділу",   Permission.READ,  rule_reviewer),
    ("редактор: зміна документів відділу рівня 1–2", Permission.WRITE, rule_editor),
    ("аудитор: читання в робочі години 08:00–20:00", Permission.READ,  rule_auditor),
    ("адміністратор: повні права на документи ІТ",   Permission.ADMIN, rule_admin),
]
 
def make_policy(sod=True, hour=None):
    """sod=False — без правила D4; hour — фіксована година."""
    policy = VariantPolicy()
    if hour is not None:
        policy.current_hour = lambda: hour
 
    for name, (dept, clearance, roles) in USERS.items():
        policy.add_subject(name, dept=dept, clearance=clearance, roles=roles)
 
    for name, (dept, level) in DOCUMENTS.items():
        policy.add_object(name, dept=dept, level=level)
 
    for title, perm, check in RULES:
        policy.add_rule(title, perm, check)
 
    policy.grant("petro", "rep05", Permission.READ)
 
    if sod:
        for role1, role2 in INCOMPATIBLE_ROLES:
            policy.add_conflict(role1, role2)
 
    return policy
 
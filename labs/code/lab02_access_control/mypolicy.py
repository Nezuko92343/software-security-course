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
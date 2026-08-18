"""Tool classification. Operator-declared; unclassified => irreversible."""
import fnmatch


class ToolClasses:
    def __init__(self, table: dict):
        self.table = table
        self.default = table.get("default", "irreversible")

    def classify(self, server, tool) -> str:
        key = f"{server}.{tool}"
        for cls in ("read", "write", "irreversible", "metered"):
            for pat in self.table.get(cls, []):
                if fnmatch.fnmatch(key, pat) or fnmatch.fnmatch(tool, pat):
                    return cls
        return self.default


DEFAULT_TABLE = {
    "read":         ["*search*", "*list*", "*get*", "*read*", "*load*"],
    "write":        ["*update*", "*create*", "*post*", "*place_order*"],
    "irreversible": ["*send_money*", "*transfer*", "*delete*", "venmo.*"],
    "metered":      ["*process-text*"],
    "default": "irreversible",
}

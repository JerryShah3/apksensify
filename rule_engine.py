import os
import yaml
import re


class RuleEngine:
    def __init__(self, rules_dir="rules"):
        self.rules_dir = rules_dir
        self.rules = self.load_rules()

    def load_rules(self):
        compiled = {}

        for file in os.listdir(self.rules_dir):
            if file.endswith(".yaml") and file != "exploit.yaml":
                path = os.path.join(self.rules_dir, file)

                with open(path, "r") as f:
                    raw = yaml.safe_load(f)

                for name, meta in raw.items():
                    compiled[name] = {
                        "pattern": re.compile(meta["regex"]),
                        "severity": meta["severity"].lower(),
                        "description": meta.get("description", "")
                    }

        return compiled

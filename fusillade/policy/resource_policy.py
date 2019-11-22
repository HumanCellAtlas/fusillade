import json
from typing import List


def combine(policies: List[str]) -> str:
    statements = []
    for p in policies:
        statements.extend(json.loads(p)['Statement'])
    return json.dumps(dict(Version="2012-10-17", Statement=statements))

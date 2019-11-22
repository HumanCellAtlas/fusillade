import json
from typing import Dict, Any, Union


def get_json_file(file_name) -> Dict[str, Any]:
    with open(file_name, 'r') as fp:
        return json.load(fp)


def json_equal(a: Union[dict, str], b: Union[dict, str]):
    a = json.loads(a) if isinstance(a, str) else a
    a = json.dumps(a, sort_keys=True)
    b = json.loads(b) if isinstance(b, str) else b
    b = json.dumps(b, sort_keys=True)
    return a == b

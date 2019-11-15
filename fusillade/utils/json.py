import json
from typing import Dict, Any


def get_json_file(file_name) -> Dict[str, Any]:
    with open(file_name, 'r') as fp:
        return json.load(fp)
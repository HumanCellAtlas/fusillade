obj_type_path = dict(
    group='/group/',
    index='/index/',
    user='/user/',
    policy='/policy/',
    role='/role/',
    resource='/resource/'
)


def get_obj_type_path(obj_type: str) -> str:
    obj_type = obj_type.lower()
    try:
        return obj_type_path[obj_type]
    except KeyError:
        if obj_type.startswith('resource'):
            # check that it's a resource type with format resource/resource_type
            return f'/{obj_type}/id/'

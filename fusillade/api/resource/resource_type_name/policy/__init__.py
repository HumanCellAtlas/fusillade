from flask import request

from fusillade.api.paging import get_next_token, get_page
from fusillade.directory.resource import ResourceType
from fusillade.utils.authorize import authorize


@authorize(["fus:GetResources"],
           ["arn:hca:fus:*:*:resource/{resource_type_name}/policy"],
           resource_params=['resource_type_name'])
def get(token_info: dict, resource_type_name):
    next_token, per_page = get_next_token(request.args)
    return get_page(ResourceType.list_policies(), next_token, per_page, content_key='policies')

from flask import request

from fusillade.resource import ResourceType
from fusillade.utils.authorize import authorize
from fusillade.api.paging import get_next_token, get_page


@authorize(["fus:GetResources"], ["arn:hca:fus:*:*:resource/*"])
def get(token_info: dict):
    next_token, per_page = get_next_token(request.args)
    return get_page(ResourceType.list_all, next_token, per_page)


@authorize(["fus:GetResources"], ["arn:hca:fus:*:*:resource/*"])
def post(token_info: dict):
    pass
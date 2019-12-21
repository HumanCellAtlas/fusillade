from flask import request

from fusillade.api.paging import get_next_token, get_page
from fusillade.directory.resource import ResourceType
from fusillade.utils.authorize import authorize


@authorize(["fus:GetResources"], ["arn:hca:fus:*:*:resource/*"])
def get(token_info: dict):
    next_token, per_page = get_next_token(request.args)
    return get_page(ResourceType.list_all,
                    next_token,
                    per_page,
                    content_key='resources')

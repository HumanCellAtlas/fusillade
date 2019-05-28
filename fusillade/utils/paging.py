from furl import furl


def get_next_token(query_params: dict):
    next_token = query_params.get('next_token')
    per_page = int(query_params['per_page']) if query_params.get('per_page') else None
    return next_token, per_page


def build_next_url(host, path, next_token: str, per_page: int) -> str:
    return furl(host=host, path=path, query_params={'next_token': next_token,
                                                    'per_page': per_page}).url


def build_link_header(links):
    """
    Builds a Link header according to RFC 5988.
    The format is a dict where the keys are the URI with the value being
    a dict of link parameters:
        {
            '/page=3': {
                'rel': 'next',
            },
            '/page=1': {
                'rel': 'prev',
            },
            ...
        }
    See https://tools.ietf.org/html/rfc5988#section-6.2.2 for registered
    link relation types.
    """
    _links = []
    for uri, params in links.items():
        link = [f"<{uri}>"]
        for key, value in params.items():
            link.append(f'{key}="{str(value)}"')
        _links.append('; '.join(link))
    return ', '.join(_links)

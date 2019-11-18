import functools
import json
import logging
import typing
from typing import List, Dict, Optional, Union, Any

from dcplib.aws import clients as aws_clients
from fusillade import User, Config
from fusillade.errors import FusilladeForbiddenException, AuthorizationException, FusilladeBadRequestException

logger = logging.getLogger(__name__)
iam = aws_clients.iam
simulate_custom_policy_paginator = iam.get_paginator('simulate_custom_policy')


def get_policy_statement(evaluation_results: List[Dict[str, Any]],
                         policies: List[Dict[str, Any]],
                         resource_policy: str = None) -> List[Dict[str, Any]]:
    """
    Parses the response from simulate_custom_policy and adds the policy statements that matched to the results.

    :param evaluation_results:
    :param policies:
    :return:
    """
    for evaluation_result in evaluation_results:
        for ms in evaluation_result['MatchedStatements']:
            begin = ms['StartPosition']['Column']
            end = ms['EndPosition']['Column']
            try:
                policy_index = int(ms['SourcePolicyId'].split('.')[-1]) - 1
            except ValueError:
                if resource_policy:
                    ms['statement'] = resource_policy[begin:end]
                    ms['SourcePolicyId'] = 'ResourcePolicy'
                    ms['SourcePolicyType'] = 'ResourcePolicy'
                else:
                    logging.warning({"msg": "Failed to parse evaluation response.",
                                     "matched_statement": ms,
                                     "policies": policies,
                                     "resource_policy": resource_policy})
                    continue
            else:
                policy = policies[policy_index]
                ms['SourcePolicyId'] = policy['name']
                ms['SourcePolicyType'] = policy['type']
    return evaluation_results


def evaluate_policy(
        principal: str,
        actions: List[str],
        resources: List[str],
        policies: List[Dict[str, str]],
        resource_policy: str = None,
        context_entries: List[Dict] = None
) -> Dict[str, Any]:
    context_entries = context_entries if context_entries else []
    eval_results = []
    params = dict(
        PolicyInputList=[policy['policy_document'] for policy in policies],
        ActionNames=actions,
        ResourceArns=resources,
        ContextEntries=[
            {
                'ContextKeyName': 'fus:user_email',
                'ContextKeyValues': [principal],
                'ContextKeyType': 'string'
            }, *context_entries
        ],
        PaginationConfig={
            'MaxItems': 20,
            'PageSize': 8
        }
    )
    if resource_policy:
        params.update(
            ResourcePolicy=resource_policy,
            CallerArn='arn:aws:iam::634134578715:user/anyone')  # TODO this should be an AWS fusillade service account
    for _response in simulate_custom_policy_paginator.paginate(**params):
        logger.info(_response['ResponseMetadata'])
        logger.debug(_response['EvaluationResults'])
        eval_results.extend(get_policy_statement(_response['EvaluationResults'], policies, resource_policy))
    eval_decisions = [er['EvalDecision'] for er in eval_results]
    if 'explicitDeny' in eval_decisions:
        response = {
            'result': False,
            'reason': 'Permission is explicit denied.',
        }
    elif 'allowed' in eval_decisions:
        response = {
            'result': True,
            'reason': 'Permission is allowed.',
        }
    else:
        response = {
            'result': False,
            'reason': 'Permission was implicitly denied.'
        }
    response['evaluation_results'] = eval_results
    return response


def get_email_claim(token_info):
    email = token_info.get(Config.oidc_email_claim) or token_info.get('email')
    if email:
        return email
    else:
        raise FusilladeForbiddenException(f"{Config.oidc_email_claim} claim is missing from token.")


def assert_authorized(user, actions, resources, context_entries=None):
    """
    Asserts a user has permission to perform actions on resources.

    :param user:
    :param actions:
    :param resources:
    :param context_entries:
    :return:
    """
    u = User(user)
    context_entries = context_entries if context_entries else []
    try:
        authz_params = u.get_authz_params()
    except AuthorizationException:
        raise FusilladeForbiddenException(detail="User must be enabled to make authenticated requests.")
    else:
        context_entries.extend(restricted_context_entries(authz_params))
        if not evaluate_policy(user, actions, resources, authz_params['policies'], context_entries)['result']:
            logger.info(dict(message="User not authorized.", user=u._path_name, action=actions, resources=resources))
            raise FusilladeForbiddenException()
        else:
            logger.info(dict(message="User authorized.", user=u._path_name, action=actions,
                             resources=resources))


restricted_set = {'fus:groups', 'fus:roles', 'fus:user_email'}


def restricted_context_entries(authz_params):
    """
    Restricts context_entries from containing reserved entries.

    :param authz_params:
    :return:
    """
    try:
        return format_context_entries({'fus:groups': 'group', 'fus:roles': 'role'}, authz_params)
    except KeyError:
        FusilladeBadRequestException("Invalid context entry type.")


def format_resources(resources: List[str], resource_param: List[str], kwargs: Dict[str, Union[List[str], str]]):
    """
    >>> resources=['hello/{user_name}']
    >>> resource_param=['user_name']
    >>> kwargs={'user_name': "bob"}
    >>> x = format_resources(resources, resource_param, kwargs)
    >>> x == ['hello/bob']

    :param resources:
    :param resource_param:
    :param kwargs:
    :return:
    """
    _rp = dict()
    for key in resource_param:
        v = kwargs.get(key)
        if isinstance(v, str):
            _rp[key] = v
    return [resource.format_map(_rp) for resource in resources]


context_type_mapping = {
    str: 'string',
    # int: 'numeric',  # TODO: add support
    # float: 'numeric',  # TODO: add support
    # bool: 'bool'  # TODO: add support
}


def format_context_entries(context_entries: Dict[str, str],
                           kwargs: Dict[str, Union[List[str], str]],
                           restricted: List[str] = None) -> List[Dict]:
    """
    >>> context_entries={"fus:context": "user_name", "fus:groups": "group"}
    >>> kwargs={'user_name': "bob", 'group': ['g1', 'g2']}
    >>> x = format_resources(context_entries, kwargs)
    >>> x == [{"ContextKeyName": "fus:context","ContextKeyValues":["bob"],"ContextKeyType": "string"},
    >>>       {"ContextKeyName": "fus:groups","ContextKeyValues":["g1", "g2"],"ContextKeyType": "stringList"}]

    :param context_entries:
    :param kwargs:
    :param restricted: A list of context variables not allowed.
    :return:
    """
    _ce = []
    restricted = restricted if restricted else []
    for key, value in context_entries.items():
        if key not in restricted:
            v = kwargs.get(value)
            if v is None:
                continue
            elif isinstance(v, list) and v:
                v_type = type(v[0])
                if all(isinstance(i, v_type) for i in v):
                    suffix = "List"
            else:
                v_type = type(v)
                v = [v]
                suffix = ""
            _ce.append({
                'ContextKeyName': key,
                'ContextKeyValues': v,
                'ContextKeyType': f"{context_type_mapping[v_type]}{suffix}"
            })
    return _ce


def authorize(actions: List[str],
              resources: List[str],
              resource_params: Optional[List[str]] = None,
              context_entries: Optional[Dict[str, str]] = None
              ):
    """
    A decorator for assert_authorized

    :param actions: The actions passed to assert_authorized
    :param resources: The resources passed to assert_authorized
    :param resource_params: Keys to extract from kwargs and map into the resource strings.
    :param context_entries: Keys to extract from kwargs and map into iam policy context variables
    :return:
    """

    def decorate(func):
        @functools.wraps(func)
        def call(*args, **kwargs):
            assert_authorized(get_email_claim(kwargs['token_info']),
                              actions,
                              format_resources(resources, resource_params, kwargs) if resource_params else resources,
                              format_context_entries(context_entries, kwargs,
                                                     restricted_set) if context_entries else None
                              )
            return func(*args, **kwargs)

        return call

    return decorate


def health_checks() -> typing.Dict[str, str]:
    try:
        iam.simulate_custom_policy(
            PolicyInputList=[json.dumps({
                "Version": "2012-10-17",
                "Statement": [{
                    "Sid": "DefaultRole",
                    "Effect": "Deny",
                    "Action": ["fake:action"],
                    "Resource": "fake:resource"
                }]})],
            ActionNames=["fake:action"],
            ResourceArns=["arn:aws:iam::123456789012:user/Bob"])
    except Exception:
        return dict(iam_health_status='unhealthy')
    else:
        return dict(iam_health_status='ok')

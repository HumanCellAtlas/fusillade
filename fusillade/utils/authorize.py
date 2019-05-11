import json
import logging
import typing

from dcplib.aws import clients as aws_clients

from fusillade import User, directory
from fusillade.errors import FusilladeForbiddenException

logger = logging.getLogger(__name__)
iam = aws_clients.iam


def evaluate_policy(
        principal: str,
        actions: typing.List[str],
        resources: typing.List[str],
        policies: typing.List[str],
) -> bool:
    result = iam.simulate_custom_policy(
        PolicyInputList=policies,
        ActionNames=actions,
        ResourceArns=resources,
        ContextEntries=[
            {
                'ContextKeyName': 'fus:user_email',
                'ContextKeyValues': [principal],
                'ContextKeyType': 'string'
            }
        ]
    )['EvaluationResults'][0]['EvalDecision']
    return True if result == 'allowed' else False


def assert_authorized(user, actions, resources):
    u = User(directory, user)
    policies = u.lookup_policies()
    if not evaluate_policy(user, actions, resources, policies):
        logger.info(json.dumps(dict(msg="User not authorized.",user=u._path_name, action=actions, resources=resources)))
        raise FusilladeForbiddenException()
    else:
        logger.info(json.dumps(dict(msg="User authorized.",user=u._path_name, action=actions, resources=resources)))

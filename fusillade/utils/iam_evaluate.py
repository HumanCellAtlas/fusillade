import typing

from dcplib.aws import clients as aws_clients
from fusillade import User, directory

iam = aws_clients.iam


def evaluate_policy(principal: str, actions: typing.List[str], resources: typing.List[str]) -> bool:
    user = User(directory, principal)
    result = iam.simulate_custom_policy(
        PolicyInputList=user.lookup_policies(),
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

from fusillade import directory
from fusillade import User
from dcplib.aws import clients as aws_clients

simulate_custom_policy = aws_clients.iam.simulate_custom_policy


def evaluate_policy(principal, action, resource):
    user = User(directory, principal)
    result = simulate_custom_policy(
        PolicyInputList=user.lookup_policies(),
        ActionNames=[action],
        ResourceArns=[resource],
        ContextEntries=[
            {
                'ContextKeyName': 'fus:user_email',
                'ContextKeyValues': [principal],
                'ContextKeyType': 'string'
            }
        ]
    )['EvaluationResults'][0]['EvalDecision']
    result = True if result == 'allowed' else False
    return dict(principal=principal, action=action, resource=resource, result=result)

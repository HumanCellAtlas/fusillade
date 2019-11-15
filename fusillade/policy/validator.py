"""
Verifies the policy statement is syntactically correct based on AWS's IAM Policy Grammar.
A fake ActionNames and ResourceArns are used to facilitate the simulation of the policy.


"""
import json
import typing

from dcplib.aws import clients as aws_clients
from fusillade.errors import FusilladeHTTPException

iam = aws_clients.iam


def verify_iam_policy(policy: str):
    try:
        iam.simulate_custom_policy(PolicyInputList=[policy],
                                   ActionNames=["fake:action"],
                                   ResourceArns=["arn:aws:iam::123456789012:user/Bob"])
    except iam.exceptions.InvalidInputException:
        raise FusilladeHTTPException(title="Bad Request", detail="Invalid iam policy format.")


def verify_resource_policy(policy: str):
    try:
        resource = json.loads(policy)['Statement'][0]['Resource']
        if isinstance(resource, str):
            resource = [resource]
        iam.simulate_custom_policy(
            PolicyInputList=[json.dumps({"Version": "2012-10-17",
                                         "Statement": [{
                                             "Effect": "Allow",
                                             "Action": ["fake:Fake"],
                                             "Resource": "arn:hca:fus:*:*:resource/fake/1234",
                                         }]}), ],
            ActionNames=["fake:action"],
            ResourceArns=resource,
            ResourcePolicy=policy,
            CallerArn='arn:aws:iam::634134578715:user/anyone')
    except iam.exceptions.InvalidInputException:
        raise FusilladeHTTPException(title="Bad Request", detail="Invalid resource policy format.")


_policy_func = {
    "IAMPolicy": verify_iam_policy,
    "ResourcePolicy": verify_resource_policy
}


def verify_policy(policy: typing.Dict[str, any], policy_type: str):
    policy.update(Version="2012-10-17")
    _policy_func[policy_type](json.dumps(policy))

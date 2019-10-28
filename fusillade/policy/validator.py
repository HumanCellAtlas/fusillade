"""
Verifies the policy statement is syntactically correct based on AWS's IAM Policy Grammar.
A fake ActionNames and ResourceArns are used to facilitate the simulation of the policy.


"""
import json

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

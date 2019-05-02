from flask import make_response, jsonify
from fusillade.utils.iam_evaluate import evaluate_policy
from fusillade.utils.security import assert_authorized


def evaluate_policy_api(user, body):
    assert_authorized(user, ['fus:Evaluate'], ['arn:hca:fus:*:*:user'])
    result = evaluate_policy(body['principal'], body['action'], body['resource'])
    return make_response(jsonify(**body, result=result), 200)

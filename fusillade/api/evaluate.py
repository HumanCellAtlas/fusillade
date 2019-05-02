from threading import Thread
from concurrent.futures import Future
import typing

from flask import make_response, jsonify

from fusillade import User, directory

from fusillade.utils.authorize import assert_authorized, evaluate_policy


def evaluate_policy_api(user, body):
    with ThreadedAuthorize(user, ['fus:Evaluate'], ['arn:hca:fus:*:*:user']):
        policies = User(directory, body['principal']).lookup_policies()
        result = evaluate_policy(body['principal'], body['action'], body['resource'], policies)
    return make_response(jsonify(**body, result=result), 200)


def call_with_future(fn, future, args, kwargs):
    try:
        result = fn(*args, **kwargs)
        future.set_result(result)
    except Exception as exc:
        future.set_exception(exc)


def threaded(fn):
    def wrapper(*args, **kwargs):
        future = Future()
        Thread(target=call_with_future, args=(fn, future, args, kwargs)).start()
        return future

    return wrapper


class ThreadedAuthorize:
    """
    Allows us to authorize the request and evaluate the request in parallel.
    """
    def __init__(
            self,
            user: str,
            actions: typing.List[str],
            resources: typing.List[str]
    ):
        self.user = user
        self.actions = actions
        self.resources = resources

    def __enter__(self):
        self.future = self._evaluate()

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.future.result()

    @threaded
    def _evaluate(self):
        assert_authorized(self.user, self.actions, self.resources)

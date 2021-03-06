import typing
from concurrent.futures import Future
from threading import Thread

from flask import make_response, jsonify

from fusillade.directory.authorization import get_resource_authz_parameters
from fusillade.errors import AuthorizationException, ResourceNotFound
from fusillade.utils.authorize import assert_authorized, evaluate_policy, restricted_context_entries, get_email_claim


def evaluate_policy_api(token_info, body):  # TODO allow context variables to be specified in the body.
    principal = get_email_claim(token_info)
    with AuthorizeThread(principal,
                         ['fus:Evaluate'],
                         ['arn:hca:fus:*:*:user']):
        try:
            authz_params = get_resource_authz_parameters(body['principal'], body['resource'])
        except AuthorizationException:
            response = {'result': False, 'reason': "UserDisabled"}
        except ResourceNotFound as ex:
            response = {'result': False, 'reason': ex.reason, 'details': 'The requested resource does not exist.'}
        else:
            response = evaluate_policy(
                body['principal'],
                body['action'],
                body['resource'],
                authz_params['IAMPolicy'],
                authz_params.get('ResourcePolicy'),
                context_entries=restricted_context_entries(authz_params))
    return make_response(jsonify(**response), 200)


class AuthorizeThread:
    """
    Authorize the requester in a separate thread while executing the request. This is safe only when performing
    read operations. If authorization fails a 403 is returned and the original request results are discarded.
    """

    def __init__(
            self,
            user: str,
            actions: typing.List[str],
            resources: typing.List[str]
    ):
        self.args = (user, actions, resources)

    def __enter__(self):
        self.future = self.evaluate()

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.future.result()

    @staticmethod
    def _call_with_future(fn, future, args):
        """
        Returns the result of the wrapped threaded function.
        """
        try:
            result = fn(*args)
            future.set_result(result)
        except Exception as exc:
            future.set_exception(exc)

    def evaluate(self):
        future = Future()
        Thread(target=self._call_with_future, args=(assert_authorized, future, self.args)).start()
        return future

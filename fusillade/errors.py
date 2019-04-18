import logging
import traceback
import requests

import werkzeug.exceptions as werkzeug_exception
from connexion.exceptions import ProblemException

logger = logging.getLogger(__name__)


class FusilladeException(Exception):
    pass


class FusilladeHTTPException(ProblemException):
    pass


class FusilladeBindingException(FusilladeHTTPException, werkzeug_exception.BadRequest):
    def __init__(self, detail, *args, **kwargs) -> None:
        super().__init__(status=requests.codes.bad_request, title="illegal_arguments", detail=detail,
                         ext={'stacktrace': traceback.format_exc()}, *args,
                         **kwargs)


class FusilladeForbiddenException(FusilladeHTTPException, werkzeug_exception.Forbidden):
    def __init__(self, detail: str = "User is not authorized to access this resource",
                 *args, **kwargs) -> None:
        super().__init__(status=requests.codes.forbidden,
                         title="Forbidden",
                         detail=detail,
                         *args, **kwargs)

import collections
import functools
import logging
import os
import re

import chalice
import requests

from connexion import FlaskApp
from connexion.decorators.validation import ParameterValidator, RequestBodyValidator
from connexion.resolver import RestyResolver

from fusillade import FusilladeBindingException, Config


class FusilladeParameterValidator(ParameterValidator):
    """
    The ParameterValidator provided by Connexion immediately returns a value if the validation fails.  Therefore, our
    code is never invoked, and the common_error_handler in the connexion.App object is never called.  This means error
    messsages are not returned using our standard error formats.

    The solution is to trap the validation results, and if it fails, exit the validation flow.  We catch the exception
    at the top level where the various validators are called, and return a value according to our specs.
    """

    @staticmethod
    def validate_parameter(*args, **kwargs):
        result = ParameterValidator.validate_parameter(*args, **kwargs)
        if result is not None:
            raise FusilladeBindingException(result)
        return result

    def __call__(self, function):
        origwrapper = super().__call__(function)

        @functools.wraps(origwrapper)
        def wrapper(request):
            try:
                return origwrapper(request)
            except FusilladeBindingException as ex:
                return ex.to_problem()

        return wrapper


class FusilladeRequestBodyValidator(RequestBodyValidator):
    """
    The RequestBodyValidator provided by Connexion immediately returns a value if the validation fails.  Therefore, our
    code is never invoked, and the common_error_handler in the connexion.App object is never called.  This means error
    messsages are not returned using our standard error formats.

    The solution is to trap the validation results, and if it fails, exit the validation flow.  We catch the exception
    at the top level where the various validators are called.
    """

    def validate_schema(self, *args, **kwargs):
        result = super().validate_schema(*args, **kwargs)
        if result is not None:
            raise FusilladeBindingException(result.body['detail'])
        return result

    def __call__(self, function):
        origwrapper = super().__call__(function)

        @functools.wraps(origwrapper)
        def wrapper(request):
            try:
                return origwrapper(request)
            except FusilladeBindingException as ex:
                return ex.to_problem()

        return wrapper


class ChaliceWithConnexion(chalice.Chalice):
    """
    Subclasses Chalice to host a Connexion app, route and proxy requests to it.
    """

    def __init__(self, swagger_spec_path, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.swagger_spec_path = swagger_spec_path
        self.connexion_app = self.create_connexion_app()
        self.connexion_full_dispatch_request = self.connexion_app.app.full_dispatch_request
        self.connexion_request_context = self.connexion_app.app.test_request_context
        self.trailing_slash_routes = []
        routes = collections.defaultdict(list)
        for rule in self.connexion_app.app.url_map.iter_rules():
            route = re.sub(r"<(.+?)(:.+?)?>", r"{\1}", rule.rule)
            stripped_route = route.rstrip("/")
            if route.endswith("/"):
                self.trailing_slash_routes.append(stripped_route)
            routes[stripped_route] += rule.methods
        for route, methods in routes.items():
            self.route(route, methods=list(set(methods) - {"OPTIONS"}), cors=True)(self.dispatch)

    def create_connexion_app(self):
        app = FlaskApp('fusillade')
        # The Flask/Connection app's logger has its own multi-line formatter and configuration. Rather than suppressing
        # it we let it do its thing, give it a special name and only enable it if Fusillade_DEBUG > 1.
        # Most of the Fusillade web app's logging is done through the FusilladeChaliceApp.app logger not the Flask
        # app's logger.
        app.app.logger_name = 'fus.api'
        debug = Config.debug_level() > 0
        app.app.debug = debug
        app.app.logger.info('Flask debug is %s.', 'enabled' if debug else 'disabled')

        validator_map = {
            'body': FusilladeRequestBodyValidator,
            'parameter': FusilladeParameterValidator,
        }

        resolver = RestyResolver("fusillade.api", collection_endpoint_name="list")
        app.add_api(self.swagger_spec_path,
                    validator_map=validator_map,
                    resolver=resolver,
                    validate_responses=True,
                    arguments=os.environ,
                    options={"swagger_path": self.swagger_spec_path})
        return app

    def dispatch(self, *args, **kwargs):
        """
        This is the main entry point into the connexion application.

        :param args:
        :param kwargs:
        :return:
        """
        cr = self.current_request
        context = cr.context
        uri_params = cr.uri_params or {}
        method = cr.method
        query_params = cr.query_params
        path = context["resourcePath"].format(**uri_params)
        if context["resourcePath"] in self.trailing_slash_routes:
            if context["path"].endswith("/"):
                path += "/"
            else:
                return chalice.Response(status_code=requests.codes.found, headers={"Location": path + "/"}, body="")
        req_body = cr.raw_body if cr._body is not None else None
        base_url = "https://{}".format(cr.headers["host"]) if cr.headers.get("host") else os.environ["API_DOMAIN_NAME"]
        # TODO figure out of host should be os.environ["API_DOMAIN_NAME"]

        self.log.info(
            """[request] "%s %s" %s %s "%s" %s""",
            method,
            path,
            context['identity']['sourceIp'],
            cr.headers.get('content-length', '-'),
            cr.headers.get('user-agent'),
            str(query_params) if query_params is not None else '',
        )
        with self.connexion_request_context(path=path,
                                            base_url=base_url,
                                            query_string=cr.query_params,
                                            method=method,
                                            headers=list(cr.headers.items()),
                                            data=req_body,
                                            environ_base=cr.stage_vars):
            try:
                flask_res = self.connexion_full_dispatch_request()
                status_code = flask_res._status_code
            except Exception:
                self.log.exception('The request failed!')
            finally:
                self.log.info(
                    "[dispatch] \"%s %s\" %s%s",
                    method,
                    path,
                    str(status_code),
                    ' ' + str(query_params) if query_params is not None else '',
                )
        res_headers = dict(flask_res.headers)
        res_headers.update(
            {"X-AWS-REQUEST-ID": self.lambda_context.aws_request_id,
             "Strict-Transport-Security": "max-age=31536000; includeSubDomains; preload"})
        res_headers.pop("Content-Length", None)
        return chalice.Response(status_code=status_code,
                                headers=res_headers,
                                body=b"".join([c for c in flask_res.response]).decode())


class ChaliceWithLoggingConfig(chalice.Chalice):
    """
    Subclasses Chalice to configure all Python loggers to our liking.
    """
    silence_debug_loggers = ["botocore"]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        logging.basicConfig()
        if Config.debug_level() == 0:
            self.debug = False
        elif Config.debug_level() == 1:
            self.debug = True
            logging.root.setLevel(logging.INFO)
        elif Config.debug_level() > 1:
            self.debug = True
            logging.root.setLevel(logging.DEBUG)
            for logger_name in self.silence_debug_loggers:
                logging.getLogger(logger_name).setLevel(logging.INFO)


class FusilladeServer(ChaliceWithConnexion, ChaliceWithLoggingConfig):
    pass

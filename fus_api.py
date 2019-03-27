#!/usr/bin/env python

"""
Entry point for starting a local test Fusillade API server.
"""
import contextlib
import socket

import chalice.config
from chalice.cli import CLIFactory
import sys
import logging
import argparse
import os

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--host", default="localhost")
parser.add_argument("--port", type=int, default=8000)
parser.add_argument("--no-debug", dest="debug", action="store_false",
                    help="Disable Chalice/Connexion/Flask debug mode")
parser.add_argument("--project-dir", help=argparse.SUPPRESS,
                    default=os.path.join(os.path.dirname(__file__), "chalice"))
parser.add_argument("--log-level",
                    help=str([logging.getLevelName(i) for i in range(0, 60, 10)]),
                    choices={logging.getLevelName(i) for i in range(0, 60, 10)},
                    default=logging.DEBUG)
args = parser.parse_args()


if "FUS_HOME" not in os.environ:
    parser.exit('Please run "source environment" in the fusillade repo root directory')

logging.basicConfig(level=args.log_level, stream=sys.stderr)

# When running `chalice local`, a stdout logger is configured
# so you'll see the same stdout logging as you would when
# running in lambda.  This is configuring the root logger.
# The app-specific logger (app.log) will still continue
# to work.
logging.basicConfig(stream=sys.stdout)

factory = CLIFactory(project_dir=args.project_dir, debug=args.debug)
app_obj = factory.load_chalice_app()
app_obj._override_exptime_seconds = 86400  # something large.  sys.maxsize causes chalice to flip.
config = chalice.config.Config.create(chalice_stage=os.environ["FUS_DEPLOYMENT_STAGE"],
                                      lambda_timeout=app_obj._override_exptime_seconds)
server = factory.create_local_server(app_obj=app_obj, config=config, host=args.host, port=args.port)
server.serve_forever()

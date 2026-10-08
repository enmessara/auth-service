"""One error type + JSON handlers. Error bodies follow the OAuth2 shape."""
import logging

from flask import jsonify
from werkzeug.exceptions import HTTPException

log = logging.getLogger(__name__)


class ApiError(Exception):
    def __init__(self, status, error, description=None, headers=None):
        super().__init__(error)
        self.status = status
        self.error = error
        self.description = description
        self.headers = headers or {}


def _body(error, description=None):
    body = {"error": error}
    if description:
        body["error_description"] = description
    return body


def register_error_handlers(app):
    @app.errorhandler(ApiError)
    def _api_error(e):
        return jsonify(_body(e.error, e.description)), e.status, e.headers

    @app.errorhandler(HTTPException)
    def _http_error(e):
        names = {400: "bad_request", 404: "not_found", 405: "method_not_allowed",
                 413: "payload_too_large", 415: "unsupported_media_type"}
        return jsonify(_body(names.get(e.code, "http_error"), e.description)), e.code

    @app.errorhandler(Exception)
    def _unhandled(e):
        log.exception("unhandled error")
        return jsonify(_body("server_error", "Internal server error")), 500

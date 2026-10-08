from flask import request

from ..errors import ApiError


def json_body() -> dict:
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        raise ApiError(400, "invalid_request", "A JSON object body is required")
    return data


def int_arg(name, default, lo, hi):
    raw = request.args.get(name)
    if raw is None:
        return default
    try:
        return max(lo, min(hi, int(raw)))
    except ValueError:
        raise ApiError(400, "invalid_request", f"{name} must be an integer")

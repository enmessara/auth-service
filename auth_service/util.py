import re
import time
import uuid
from datetime import datetime, timezone

EMAIL_RE = re.compile(r"^[^@\s]{1,64}@[^@\s]{1,255}\.[^@\s]{2,}$")


def now() -> int:
    """Current epoch seconds. Always call as util.now() so tests can patch it."""
    return int(time.time())


def new_id() -> str:
    return str(uuid.uuid4())


def iso(epoch) -> str | None:
    if epoch is None:
        return None
    return datetime.fromtimestamp(epoch, timezone.utc).isoformat(timespec="seconds")

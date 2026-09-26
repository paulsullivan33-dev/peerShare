"""Bounded, versioned node profiles; no network or application state mutations."""

import json
import uuid
from pathlib import Path

PROTOCOL_VERSION = 1
PROFILE_TTL_SECONDS = 90
MAX_PROFILE_BYTES = 4096
MAX_QUERY_RESULTS = 8
AVAILABILITY = ("ready", "busy", "draining")


def text(value: object, field: str, maximum: int = 64) -> str:
    if (not isinstance(value, str) or not value.strip() or len(value) > maximum
            or any(ord(character) < 32 or ord(character) == 127 for character in value)):
        raise ValueError(f"{field} must be nonempty text of at most {maximum} characters")
    return value


def integer(value: object, field: str, minimum: int, maximum: int) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise ValueError(f"{field} must be an integer between {minimum} and {maximum}")
    return value


def identifier(value: object, field: str) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{field} must be a UUID")
    try:
        parsed = uuid.UUID(value)
    except ValueError as error:
        raise ValueError(f"{field} must be a UUID") from error
    if str(parsed) != value or parsed.int == 0:
        raise ValueError(f"{field} must be a canonical nonzero UUID")
    return value


def load_node_id(path: str | Path) -> str:
    """Exclusive creation avoids overwriting an existing identity or corrupt file."""
    path = Path(path)
    try:
        value = path.read_text(encoding="utf-8").strip()
    except FileNotFoundError:
        value = str(uuid.uuid4())
        try:
            with path.open("x", encoding="utf-8") as output:
                output.write(value + "\n")
        except FileExistsError:
            value = path.read_text(encoding="utf-8").strip()
    return identifier(value, "saved node_id")


def validate_profile(value: object) -> dict:
    if not isinstance(value, dict):
        raise ValueError("profile must be an object")
    if len(json.dumps(value, allow_nan=False).encode()) > MAX_PROFILE_BYTES:
        raise ValueError("profile exceeds 4096 bytes")
    required = {"node_id", "instance_id", "name", "protocol_version", "sequence",
                "capabilities", "services", "availability", "resources", "ttl_seconds"}
    if set(value) != required:
        raise ValueError("profile fields do not match protocol version 1")
    identifier(value["node_id"], "node_id")
    identifier(value["instance_id"], "instance_id")
    text(value["name"], "name", 128)
    integer(value["protocol_version"], "protocol_version", PROTOCOL_VERSION, PROTOCOL_VERSION)
    integer(value["sequence"], "sequence", 0, 2**63 - 1)
    integer(value["ttl_seconds"], "ttl_seconds", 1, PROFILE_TTL_SECONDS)
    if value["availability"] not in AVAILABILITY:
        raise ValueError("availability must be ready, busy, or draining")
    capabilities = value["capabilities"]
    if not isinstance(capabilities, list) or len(capabilities) > 16:
        raise ValueError("capabilities must be a list of at most 16 names")
    for capability in capabilities:
        text(capability, "capability")
    if len(set(capabilities)) != len(capabilities):
        raise ValueError("capabilities must be unique")
    services = value["services"]
    if not isinstance(services, list) or len(services) > 16:
        raise ValueError("services must be a list of at most 16 services")
    names = set()
    for service in services:
        if not isinstance(service, dict) or set(service) != {"name", "capability", "port"}:
            raise ValueError("each service requires name, capability, and port")
        text(service["name"], "service name")
        text(service["capability"], "service capability")
        integer(service["port"], "service port", 1, 65535)
        if service["capability"] not in capabilities or service["name"] in names:
            raise ValueError("services require a declared capability and unique name")
        names.add(service["name"])
    resources = value["resources"]
    if not isinstance(resources, dict) or len(resources) > 16:
        raise ValueError("resources must contain at most 16 counters")
    for key, count in resources.items():
        text(key, "resource name")
        integer(count, "resource count", 0, 2**63 - 1)
    # Return a detached JSON value so callers cannot mutate validated state.
    return json.loads(json.dumps(value))


def make_profile(node_id: str, name: str, capabilities: list | None = None,
                 services: list | None = None, availability: str = "ready",
                 resources: dict | None = None) -> dict:
    return validate_profile({
        "node_id": node_id, "instance_id": str(uuid.uuid4()), "name": name,
        "protocol_version": PROTOCOL_VERSION, "sequence": 0,
        "capabilities": capabilities or [], "services": services or [],
        "availability": availability, "resources": resources or {},
        "ttl_seconds": PROFILE_TTL_SECONDS,
    })

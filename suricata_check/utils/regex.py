"""The `suricata_check.utils.regex` module contains regular expressions for matching various parts of rules."""

import importlib.util
import logging
from functools import lru_cache
from typing import Iterable, Sequence

import idstools.rule

logger = logging.getLogger(__name__)

# Import the fastest regex provider available:
if importlib.util.find_spec("regex") is not None:
    logger.info("Detected regex module as installid, using it.")
    import regex as regex_provider
else:
    logger.warning(
        """Did not detect regex module as installed, using re instead.
To increase suricata-check processing speed, consider isntalling the regex module \
by running `pip install suricata-check[performance]`.""",
    )
    import re as regex_provider

LRU_CACHE_SIZE = 10

ADDRESS_GROUPS = (
    "HOME_NET",
    "EXTERNAL_NET",
    "HTTP_SERVERS",
    "SMTP_SERVERS",
    "SQL_SERVERS",
    "DNS_SERVERS",
    "TELNET_SERVERS",
    "AIM_SERVERS",
    "DC_SERVERS",
    "DNP3_SERVER",
    "DNP3_CLIENT",
    "MODBUS_CLIENT",
    "MODBUS_SERVER",
    "ENIP_CLIENT",
    "ENIP_SERVER",
)


PORT_GROUPS = (
    "HTTP_PORTS",
    "SHELLCODE_PORTS",
    "ORACLE_PORTS",
    "SSH_PORTS",
    "DNP3_PORTS",
    "MODBUS_PORTS",
    "FILE_DATA_PORTS",
    "FTP_PORTS",
    "GENEVE_PORTS",
    "VXLAN_PORTS",
    "TEREDO_PORTS",
)

ALL_VARIABLES = ADDRESS_GROUPS + PORT_GROUPS

CLASSTYPES = (
    "not-suspicious",
    "unknown",
    "bad-unknown",
    "attempted-recon",
    "successful-recon-limited",
    "successful-recon-largescale",
    "attempted-dos",
    "successful-dos",
    "attempted-user",
    "unsuccessful-user",
    "successful-user",
    "attempted-admin",
    "successful-admin",
    # NEW CLASSIFICATIONS
    "rpc-portmap-decode",
    "shellcode-detect",
    "string-detect",
    "suspicious-filename-detect",
    "suspicious-login",
    "system-call-detect",
    "tcp-connection",
    "trojan-activity",
    "unusual-client-port-connection",
    "network-scan",
    "denial-of-service",
    "non-standard-protocol",
    "protocol-command-decode",
    "web-application-activity",
    "web-application-attack",
    "misc-activity",
    "misc-attack",
    "icmp-event",
    "inappropriate-content",
    "policy-violation",
    "default-login-attempt",
    # Update
    "targeted-activity",
    "exploit-kit",
    "external-ip-check",
    "domain-c2",
    "pup-activity",
    "credential-theft",
    "social-engineering",
    "coin-mining",
    "command-and-control",
)
# TODO: The things below are called keywords (for options); should rename
NON_FUNCTIONAL_OPTIONS = (
    "msg",
    "classtype",
    "sid",
    "gid",
    "rev",
    "metadata",
    "reference",
    "target",
    "priority",
)

FLOW_OPTIONS = ("flow", "flow.age", "flowint")

STREAM_OPTIONS = ("stream_size",)

FLOW_STREAM_OPTIONS: Sequence[str] = tuple(
    sorted(set(FLOW_OPTIONS).union(STREAM_OPTIONS)),
)

STICKY_BUFFER_NAMING = {
    "http_header": "http.header",
    "file_data": "file.data",
    "dns_query": "dns.query",
    "ja3_hash": "ja3.hash",
}

OTHER_BUFFERS = (
    "http.header_names",
    "http.header.raw",
    "http.protocolhttp.location",
    "http.stat_msg",
    "http.uri",
    "http.uri.raw",
    "http.host",
    "http.referer",
    "http.user_agent",
    "http.cookie",
    "http.connection",
    "http.accept",
    "http.accept_lang",
    "http.server",
    "http.content_type",
    "http.method",
    "http.request_line",
    "http.request_body",
    "http.response_body",
    "http.start",
    "tls.sni",
    "tls.certs",
    "tls.cert_subject",
    "tls.cert_issuer",
)

BUFFER_OPTIONS: Sequence[str] = tuple(
    sorted(
        set(STICKY_BUFFER_NAMING.keys())
        .union(STICKY_BUFFER_NAMING.values())
        .union(OTHER_BUFFERS),
    ),
)

SIZE_OPTIONS = (
    "bsize",
    "dsize",
)

TRANSFORMATION_OPTIONS = (
    "dotprefix",
    "strip_whitespace",
    "compress_whitespace",
    "to_lowercase",
    "to_md5",
    "to_uppercase",
    "to_sha1",
    "to_sha256",
    "pcrexformurl_decode",
    "xor",
    "header_lowercase",
    "strip_pseudo_headers",
)

CONTENT_OPTIONS = ("content", "pcre")

POINTER_MOVEMENT_OPTIONS = (
    "depth",
    "offset",
    "distance",
    "within",
)

COMPATIBILITY_MODIFIER_OPTIONS = ("rawbytes",)

MODIFIER_OPTIONS = ("nocase",)

ALL_MODIFIER_OPTIONS: Sequence[str] = tuple(
    sorted(set(COMPATIBILITY_MODIFIER_OPTIONS).union(MODIFIER_OPTIONS)),
)

MATCH_LOCATION_OPTIONS = (
    "startswith",
    "endswith",
)

OTHER_PAYLOAD_OPTIONS = (
    "isdataat",
    "byte_test",
    "byte_extract",
    "byte_jump",
)

IP_SPECIFIC_OPTIONS = ("ttl", "ip_proto")

TCP_SPECIFIC_OPTIONS = (
    "tcp.hdr",
    "tcp.flags",
    "flags",  # This is a duplicate of tcp.flags
)

UDP_SPECIFIC_OPTIONS = ("udp.hdr",)

ICMP_SPECIFIC_OPTIONS = (
    "itype",
    "icode",
    "icmp_id",
)

HTTP_SPECIFIC_OPTIONS = (
    "urilen",
    "http.header_names",
    "http.header.raw",
    "http.protocolhttp.location",
    "http.stat_msg",
    "http.uri",
    "http.uri.raw",
    "http.host",
    "http.referer",
    "http.user_agent",
    "http.cookie",
    "http.connection",
    "http.accept",
    "http.accept_lang",
    "http.server",
    "http.content_type",
    "http.method",
    "http.request_line",
    "http.request_body",
    "http.response_body",
    "http.stat_code",
    "http.content_len",
    "http.start",
)

DNS_SPECIFIC_OPTIONS = ("dns.query",)

TLS_SPECIFIC_OPTIONS = (
    "tls.sni",
    "tls.certs",
    "tls.cert_subject",
    "tls.cert_issuer",
)

SSH_SPECIFIC_OPTIONS = ("ssh_proto",)

JA3_JA4_OPTIONS = ("ja3_hash", "ja3.hash", "ja3.string")

PROTOCOL_SPECIFIC_OPTIONS = tuple(
    sorted(
        set().union(
            *(
                IP_SPECIFIC_OPTIONS,
                TCP_SPECIFIC_OPTIONS,
                UDP_SPECIFIC_OPTIONS,
                ICMP_SPECIFIC_OPTIONS,
                HTTP_SPECIFIC_OPTIONS,
                DNS_SPECIFIC_OPTIONS,
                TLS_SPECIFIC_OPTIONS,
                SSH_SPECIFIC_OPTIONS,
                JA3_JA4_OPTIONS,
            ),
        ),
    ),
)

ALL_DETECTION_OPTIONS: Sequence[str] = tuple(
    sorted(
        set().union(
            *(
                BUFFER_OPTIONS,
                SIZE_OPTIONS,
                TRANSFORMATION_OPTIONS,
                CONTENT_OPTIONS,
                POINTER_MOVEMENT_OPTIONS,
                ALL_MODIFIER_OPTIONS,
                MATCH_LOCATION_OPTIONS,
                OTHER_PAYLOAD_OPTIONS,
                PROTOCOL_SPECIFIC_OPTIONS,
            ),
        ),
    ),
)

THRESHOLD_OPTIONS = ("threshold", "detection_filter")

STATEFUL_OPTIONS = ("flowint", "flowbits", "xbits")

OTHER_OPTIONS = ("fast_pattern", "noalert", "tag")

ALL_OPTIONS = tuple(
    sorted(
        set().union(
            *(
                NON_FUNCTIONAL_OPTIONS,
                FLOW_OPTIONS,
                STREAM_OPTIONS,
                ALL_DETECTION_OPTIONS,
                THRESHOLD_OPTIONS,
                STATEFUL_OPTIONS,
                OTHER_OPTIONS,
            ),
        ),
    ),
)

METADATA_DATE_OPTIONS = (
    "created_at",
    "updated_at",
    "reviewed_at",
)

METADATA_NON_DATE_OPTIONS = (
    "attack_target",
    "affected_product",
    "confidence",
    "signature_severity",
    "performance_impact",
    "deployment",
    "malware_family",
    "cve",
    "tag",
    "mitre_tactic_id",
    "mitre_tactic_name",
    "mitre_technique_id",
    "mitre_technique_name",
    "former_sid",
    "former_category",
    "ruleset",
    "policy",
    "tls_state",
)

ALL_METADATA_OPTIONS = tuple(
    sorted(set(METADATA_DATE_OPTIONS).union(METADATA_NON_DATE_OPTIONS)),
)

IP_ADDRESS_REGEX = regex_provider.compile(r"^.*\d+\.\d+\.\d+\.\d+.*$")

GROUP_REGEX = regex_provider.compile(r"^(!)?\[(.*)\]$")
VARIABLE_GROUP_REGEX = regex_provider.compile(r"^!?\$([A-Z\_]+)$")

ACTION_REGEX = regex_provider.compile(
    r"(alert|pass|drop|reject|rejectsrc|rejectdst|rejectboth)",
)
PROTOCOL_REGEX = regex_provider.compile(r"[a-z0-3\-]+")
ADDR_REGEX = regex_provider.compile(r"[a-zA-Z0-9\$_\!\[\],\s/]+")
PORT_REGEX = regex_provider.compile(r"[a-zA-Z0-9\$_\!\[\],\s:]+")
DIRECTION_REGEX = regex_provider.compile(r"(\->|<>)")
HEADER_REGEX = regex_provider.compile(
    rf"{ACTION_REGEX.pattern}\s*{PROTOCOL_REGEX.pattern}\s*{ADDR_REGEX.pattern}\s*{PORT_REGEX.pattern}\s*{DIRECTION_REGEX.pattern}\s*{ADDR_REGEX.pattern}\s*{PORT_REGEX.pattern}",
)
OPTION_REGEX = regex_provider.compile(r"[a-z\-\._]+(:(\s*([0-9]+|.*)\s*\,?\s*)+)?;")
BODY_REGEX = regex_provider.compile(rf"\((\s*{OPTION_REGEX.pattern}\s*)*\)")
RULE_REGEX = regex_provider.compile(
    rf"^(\s*#)?\s*{HEADER_REGEX.pattern}\s*{BODY_REGEX.pattern}\s*(#.*)?$",
)


def get_regex_provider():  # noqa: ANN201
    """Returns the regex provider to be used.

    If `regex` is installed, it will return that module.
    Otherwise, it will return the `re` module instead.
    """
    return regex_provider


@lru_cache(maxsize=LRU_CACHE_SIZE)
def _escape_regex(s: str) -> str:
    # Escape the escape character first
    s = s.replace("\\", "\\\\")

    # Then escape all other characters
    # . ^ $ * + ? { } [ ] \ | ( )
    s = s.replace(".", "\\.")
    s = s.replace("^", "\\^")
    s = s.replace("$", "\\$")
    s = s.replace("*", "\\*")
    s = s.replace("+", "\\+")
    s = s.replace("?", "\\?")
    s = s.replace("{", "\\{")
    s = s.replace("}", "\\}")
    s = s.replace("[", "\\[")
    s = s.replace("]", "\\]")
    s = s.replace("|", "\\|")
    s = s.replace("(", "\\(")
    s = s.replace(")", "\\)")

    return s  # noqa: RET504


def get_options_regex(options: Iterable[str]) -> regex_provider.Pattern:
    """Returns a regular expression that can match any of the provided options."""
    return __get_options_regex(tuple(sorted(options)))


@lru_cache(maxsize=LRU_CACHE_SIZE)
def __get_options_regex(options: Sequence[str]) -> regex_provider.Pattern:
    return regex_provider.compile(
        "(" + "|".join([_escape_regex(option) for option in options]) + ")",
    )


def _is_group(entry: str) -> bool:
    if GROUP_REGEX.match(entry) is None:
        return False

    return True


def get_rule_group_entries(group: str) -> Sequence[str]:
    """Returns a list of entries in a group."""
    stripped_group = group.strip()

    if not _is_group(stripped_group):
        return [stripped_group]

    match = GROUP_REGEX.match(stripped_group)
    assert match is not None
    negated = match.group(1) == "!"

    entries = []
    for entry in match.group(2).split(","):
        stripped_entry = entry.strip()
        if _is_group(stripped_entry):
            entries += get_rule_group_entries(stripped_entry)
        else:
            entries.append(stripped_entry)

    if negated:
        entries = ["!" + entry for entry in entries]

    return entries


@lru_cache(maxsize=LRU_CACHE_SIZE)
def get_variable_groups(value: str) -> Sequence[str]:
    """Returns a list of variable groups such as $HTTP_SERVERS in a variable."""
    entries = get_rule_group_entries(value)
    variable_groups = []
    for entry in entries:
        match = VARIABLE_GROUP_REGEX.match(entry)
        if match is not None:
            variable_groups.append(match.group(1))

    return variable_groups


@lru_cache(maxsize=LRU_CACHE_SIZE)
def get_rule_body(rule: idstools.rule.Rule) -> str:
    """Returns the body of a rule."""
    match = BODY_REGEX.search(rule["raw"])

    if match is None:
        msg = f"Could not extract rule body from rule: {rule['raw']}"
        logger.critical(msg)
        raise RuntimeError(msg)

    return match.group(0)

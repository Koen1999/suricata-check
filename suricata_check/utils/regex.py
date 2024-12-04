"""The `suricata_check.utils.regex` module contains regular expressions for matching various parts of rules."""

import importlib.util
import logging
from collections.abc import Iterable, Sequence
from functools import lru_cache

import idstools.rule

_logger = logging.getLogger(__name__)

# Import the fastest regex provider available:
if importlib.util.find_spec("regex") is not None:
    _logger.info("Detected regex module as installed, using it.")
    import regex as _regex_provider
else:
    _logger.warning(
        """Did not detect regex module as installed, using re instead.
To increase suricata-check processing speed, consider isntalling the regex module \
by running `pip install suricata-check[performance]`.""",
    )
    import re as _regex_provider

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

NON_FUNCTIONAL_KEYWORDS = (
    "classtype",
    "gid",
    "metadata",
    "msg",
    "priority",
    "reference",
    "rev",
    "sid",
    "target",
)

FLOW_KEYWORDS = (
    "flow",
    "flow.age",
    "flowint",
)

STREAM_KEYWORDS = ("stream_size",)

FLOW_STREAM_KEYWORDS: Sequence[str] = tuple(
    sorted(set(FLOW_KEYWORDS).union(STREAM_KEYWORDS)),
)

STICKY_BUFFER_NAMING = {
    "dce_iface": "dce.iface",
    "dce_opnum": "dce.opnum",
    "dce_stub_data": "dce.stub_data",
    "dns_query": "dns.query",
    "file_data": "file.data",
    "http_accept": "http.accept",
    "http_accept_enc": "http.accept_enc",
    "http_accept_lang": "http.accept_lang",
    "http_client_body": "http.request_body",
    "http_connection": "http.connection",
    "http_content_len": "http.content_len",
    "http_content_type": "http.content_type",
    "http_cookie": "http.cookie",
    "http_header": "http.header",
    "http_header_names": "http.header_names",
    "http_host": "http.host",
    "http_method": "http.method",
    "http_protocol": "http.protocol",
    "http_raw_header": "http.header.raw",
    "http_raw_host": "http.host.raw",
    "http_raw_uri": "http.uri.raw",
    "http_referer": "http.referer",
    "http_request_line": "http.request_line",
    "http_response_line": "http.response_line",
    "http_server_body": "http.response_body",
    "http_start": "http.start",
    "http_stat_code": "http.stat_code",
    "http_stat_msg": "http.stat_msg",
    "http_uri": "http.uri",
    "http_user_agent": "http.user_agent",
    "ja3_hash": "ja3.hash",
    "tls_cert_fingerprint": "tls.cert_fingerprint",
    "tls_cert_issuer": "tls.cert_issuer",
    "tls_cert_serial": "tls.cert_serial",
    "tls_cert_subject": "tls.cert_subject",
    "tls_sni": "tls.sni",
}

BASE64_BUFFER_KEYWORDS = ("base64_data",)

OTHER_BUFFERS = (
    "http.location",
    "http.request_header",
    "http.response_header",
    "http.server",
    "ja3s.hash",
    "tls.certs",
    "tls.version",
)

assert set(OTHER_BUFFERS).isdisjoint(
    set(STICKY_BUFFER_NAMING.keys()).union(STICKY_BUFFER_NAMING.values())
)

BUFFER_KEYWORDS: Sequence[str] = tuple(
    sorted(
        set(STICKY_BUFFER_NAMING.keys())
        .union(STICKY_BUFFER_NAMING.values())
        .union(BASE64_BUFFER_KEYWORDS)
        .union(OTHER_BUFFERS),
    ),
)

SIZE_KEYWORDS = (
    "bsize",
    "dsize",
)

TRANSFORMATION_KEYWORDS = (
    "compress_whitespace",
    "dotprefix",
    "header_lowercase",
    "pcrexform",
    "strip_pseudo_headers",
    "strip_whitespace",
    "to_lowercase",
    "to_md5",
    "to_sha1",
    "to_sha256",
    "to_uppercase",
    "url_decode",
    "xor",
)

BASE64_TRANSFORMATION_KEYWORDS = ("base64_decode",)

ALL_TRANSFORMATION_KEYWORDS: Sequence[str] = tuple(
    sorted(set(TRANSFORMATION_KEYWORDS).union(BASE64_TRANSFORMATION_KEYWORDS)),
)

CONTENT_KEYWORDS = ("content", "pcre")

POINTER_MOVEMENT_KEYWORDS = (
    "depth",
    "distance",
    "offset",
    "pkt_data",
    "within",
)

COMPATIBILITY_MODIFIER_KEYWORDS = ("rawbytes",)

MODIFIER_KEYWORDS = ("nocase",)

ALL_MODIFIER_KEYWORDS: Sequence[str] = tuple(
    sorted(set(COMPATIBILITY_MODIFIER_KEYWORDS).union(MODIFIER_KEYWORDS)),
)

MATCH_LOCATION_KEYWORDS = (
    "endswith",
    "startswith",
)

OTHER_PAYLOAD_KEYWORDS = (
    "byte_extract",
    "byte_jump",
    "byte_test",
    "isdataat",
)

IP_SPECIFIC_KEYWORDS = (
    "ip_proto",
    "ttl",
)

TCP_SPECIFIC_KEYWORDS = (
    "ack",
    "flags",  # This is a duplicate of tcp.flags
    "seq",
    "tcp.flags",
    "tcp.hdr",
)

UDP_SPECIFIC_KEYWORDS = ("udp.hdr",)

ICMP_SPECIFIC_KEYWORDS = (
    "fragbits",
    "icode",
    "icmp_id",
    "icmp_seq",
    "itype",
)

HTTP_SPECIFIC_KEYWORDS = (
    "file.data",
    "file_data",
    "http.accept",
    "http.accept_enc",
    "http.accept_lang",
    "http.connection",
    "http.content_len",
    "http.content_len",
    "http.content_type",
    "http.cookie",
    "http.header",
    "http.header_names",
    "http.header.raw",
    "http.host",
    "http.host.raw",
    "http.location",
    "http.method",
    "http.protocol",
    "http.referer",
    "http.request_body",
    "http.request_header",
    "http.request_line",
    "http.response_body",
    "http.response_header",
    "http.response_line",
    "http.server",
    "http.start",
    "http.stat_code",
    "http.stat_code",
    "http.stat_msg",
    "http.uri",
    "http.uri.raw",
    "http.user_agent",
    "http_accept",
    "http_accept_enc",
    "http_accept_lang",
    "http_connection",
    "http_content_len",
    "http_content_len",
    "http_content_type",
    "http_cookie",
    "http_header",
    "http_header_names",
    "http_host",
    "http_location",
    "http_method",
    "http_protocol",
    "http_raw_header",
    "http_raw_host",
    "http_raw_uri",
    "http_referer",
    "http_request_line",
    "http_response_line",
    "http_server_body",
    "http_start",
    "http_stat_code",
    "http_stat_msg",
    "http_uri",
    "http_user_agent",
    "urilen",
)

DNS_SPECIFIC_KEYWORDS = (
    "dns.opcode",
    "dns.query",
    "dns_query",
)

TLS_SPECIFIC_KEYWORDS = (
    "ssl_version",
    "ssl_state",
    "tls.cert_fingerprint",
    "tls.cert_issuer",
    "tls.cert_serial",
    "tls.cert_subject",
    "tls.certs",
    "tls.sni",
    "tls.version",
    "tls_cert_fingerprint",
    "tls_cert_issuer",
    "tls_cert_serial",
    "tls_cert_subject",
    "tls_sni",
)

SSH_SPECIFIC_KEYWORDS = ("ssh_proto",)

JA3_JA4_KEYWORDS = (
    "ja3.hash",
    "ja3_hash",
    "ja3.string",
    "ja3s.hash",
)

DCERPC_SPECIFIC_KEYWORDS = (
    "dce.iface",
    "dce.opnum",
    "dce.stub_data",
    "dce_iface",
    "dce_opnum",
    "dce_stub_data",
)

FTP_KEYWORDS = ("ftpbounce", "ftpdata_command")

APP_LAYER_KEYWORDS = (
    "app-layer-event",
    "app-layer-protocol",
)

PROTOCOL_SPECIFIC_KEYWORDS = tuple(
    sorted(
        set().union(
            *(
                IP_SPECIFIC_KEYWORDS,
                TCP_SPECIFIC_KEYWORDS,
                UDP_SPECIFIC_KEYWORDS,
                ICMP_SPECIFIC_KEYWORDS,
                HTTP_SPECIFIC_KEYWORDS,
                DNS_SPECIFIC_KEYWORDS,
                TLS_SPECIFIC_KEYWORDS,
                SSH_SPECIFIC_KEYWORDS,
                DCERPC_SPECIFIC_KEYWORDS,
                JA3_JA4_KEYWORDS,
                FTP_KEYWORDS,
                APP_LAYER_KEYWORDS,
            ),
        ),
    ),
)

PERFORMANCE_DETECTION_OPTIONS = ("fast_pattern",)

LUA_KEYWORDS = ("lua", "luajit")

ALL_DETECTION_KEYWORDS: Sequence[str] = tuple(
    sorted(
        set().union(
            *(
                BUFFER_KEYWORDS,
                SIZE_KEYWORDS,
                ALL_TRANSFORMATION_KEYWORDS,
                CONTENT_KEYWORDS,
                POINTER_MOVEMENT_KEYWORDS,
                ALL_MODIFIER_KEYWORDS,
                MATCH_LOCATION_KEYWORDS,
                OTHER_PAYLOAD_KEYWORDS,
                PROTOCOL_SPECIFIC_KEYWORDS,
                PERFORMANCE_DETECTION_OPTIONS,
                LUA_KEYWORDS,
            ),
        ),
    ),
)

THRESHOLD_KEYWORDS = (
    "detection_filter",
    "threshold",
)

STATEFUL_KEYWORDS = ("flowbits", "flowint", "xbits")

OTHER_KEYWORDS = ("noalert", "tag")

ALL_KEYWORDS = tuple(
    sorted(
        set().union(
            *(
                NON_FUNCTIONAL_KEYWORDS,
                FLOW_KEYWORDS,
                STREAM_KEYWORDS,
                ALL_DETECTION_KEYWORDS,
                THRESHOLD_KEYWORDS,
                STATEFUL_KEYWORDS,
                OTHER_KEYWORDS,
            ),
        ),
    ),
)

METADATA_DATE_KEYWORDS = (
    "created_at",
    "reviewed_at",
    "updated_at",
)

METADATA_NON_DATE_KEYWORDS = (
    "affected_product",
    "attack_target",
    "confidence",
    "cve",
    "deprecation_reason",
    "deployment",
    "former_category",
    "former_sid",
    "impact_flag",
    "malware_family",
    "mitre_tactic_id",
    "mitre_tactic_name",
    "mitre_technique_id",
    "mitre_technique_name",
    "performance_impact",
    "policy",
    "ruleset",
    "signature_severity",
    "tag",
    "tls_state",
    "first_seen",
    "confidence_level",
)

ALL_METADATA_KEYWORDS = tuple(
    sorted(set(METADATA_DATE_KEYWORDS).union(METADATA_NON_DATE_KEYWORDS)),
)

IP_ADDRESS_REGEX = _regex_provider.compile(r"^.*\d+\.\d+\.\d+\.\d+.*$")

_GROUP_REGEX = _regex_provider.compile(r"^(!)?\[(.*)\]$")
_VARIABLE_GROUP_REGEX = _regex_provider.compile(r"^!?\$([A-Z\_]+)$")

_ACTION_REGEX = _regex_provider.compile(
    r"(alert|pass|drop|reject|rejectsrc|rejectdst|rejectboth)",
)
_PROTOCOL_REGEX = _regex_provider.compile(r"[a-z0-3\-]+")
_ADDR_REGEX = _regex_provider.compile(r"[a-zA-Z0-9\$_\!\[\],\s/\.]+")
_PORT_REGEX = _regex_provider.compile(r"[a-zA-Z0-9\$_\!\[\],\s:]+")
_DIRECTION_REGEX = _regex_provider.compile(r"(\->|<>)")
HEADER_REGEX = _regex_provider.compile(
    rf"{_ACTION_REGEX.pattern}\s*{_PROTOCOL_REGEX.pattern}\s*{_ADDR_REGEX.pattern}\s*{_PORT_REGEX.pattern}\s*{_DIRECTION_REGEX.pattern}\s*{_ADDR_REGEX.pattern}\s*{_PORT_REGEX.pattern}",
)
_OPTION_REGEX = _regex_provider.compile(
    r"[a-z\-\._]+\s*(:(\s*([0-9]+|.+)\s*\,?\s*)+)?;"
)
_BODY_REGEX = _regex_provider.compile(rf"\((\s*{_OPTION_REGEX.pattern}\s*)*\)")
_RULE_REGEX = _regex_provider.compile(
    rf"^(\s*#)?\s*{HEADER_REGEX.pattern}\s*{_BODY_REGEX.pattern}\s*(#.*)?$",
)


def get_regex_provider():  # noqa: ANN201
    """Returns the regex provider to be used.

    If `regex` is installed, it will return that module.
    Otherwise, it will return the `re` module instead.
    """
    return _regex_provider


@lru_cache(maxsize=LRU_CACHE_SIZE)
def __escape_regex(s: str) -> str:
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


def get_options_regex(options: Iterable[str]) -> _regex_provider.Pattern:
    """Returns a regular expression that can match any of the provided options."""
    return __get_options_regex(tuple(sorted(options)))


@lru_cache(maxsize=LRU_CACHE_SIZE)
def __get_options_regex(options: Sequence[str]) -> _regex_provider.Pattern:
    return _regex_provider.compile(
        "(" + "|".join([__escape_regex(option) for option in options]) + ")",
    )


def __is_group(entry: str) -> bool:
    if _GROUP_REGEX.match(entry) is None:
        return False

    return True


def get_rule_group_entries(group: str) -> Sequence[str]:
    """Returns a list of entries in a group."""
    stripped_group = group.strip()

    if not __is_group(stripped_group):
        return [stripped_group]

    match = _GROUP_REGEX.match(stripped_group)
    assert match is not None
    negated = match.group(1) == "!"

    entries = []
    for entry in match.group(2).split(","):
        stripped_entry = entry.strip()
        if __is_group(stripped_entry):
            entries += get_rule_group_entries(stripped_entry)
        else:
            entries.append(stripped_entry)

    if negated:
        entries = ["!" + entry for entry in entries]

    return entries


def get_variable_groups(value: str) -> Sequence[str]:
    """Returns a list of variable groups such as $HTTP_SERVERS in a variable."""
    return __get_variable_groups(value)


@lru_cache(maxsize=LRU_CACHE_SIZE)
def __get_variable_groups(value: str) -> Sequence[str]:
    entries = get_rule_group_entries(value)
    variable_groups = []
    for entry in entries:
        match = _VARIABLE_GROUP_REGEX.match(entry)
        if match is not None:
            variable_groups.append(match.group(1))

    return variable_groups


def get_rule_body(rule: idstools.rule.Rule) -> str:
    """Returns the body of a rule."""
    return __get_rule_body(rule)


@lru_cache(maxsize=LRU_CACHE_SIZE)
def __get_rule_body(rule: idstools.rule.Rule) -> str:
    match = _BODY_REGEX.search(rule["raw"])

    if match is None:
        msg = f"Could not extract rule body from rule: {rule['raw']}"
        _logger.critical(msg)
        raise RuntimeError(msg)

    return match.group(0)


def is_valid_rule(rule: idstools.rule.Rule) -> bool:
    """Checks if a rule is valid."""
    if _RULE_REGEX.match(rule["raw"]) is None:
        return False

    return True

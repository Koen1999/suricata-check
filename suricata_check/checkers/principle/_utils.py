MESSAGES: dict[str, str] = {
    "000": """No Limited Proxy, \
the rule does not detect a characteristic that relates directly to a malicious action, making it potentially noisy.""",
    "001": """No Successful Malicious Action, \
the rule does not distinguish between successful and unsuccessful malicious actions, making it potentially noisy.""",
    "002": """No Alert Throttling, \
the rule does not utilize the threshold limit option` to prevent alert flooding, making it potentially noisy.\n
Consider setting a threshold limit to prevent alert flooding.\n
Using track by_both is considered to be safe if unsure which to use.""",
    "003": """No Exceptions, \
the rule does not include any exceptions for commom benign traffic, making it potentially noisy.\n
Consider identifying common benign traffic on which the rule may trigger and add exceptions to the rule.""",
    "004": """No Generalized Characteristic, \
the rule does detect a characteristic that is so specific that it is unlikely generalize.""",
    "005": """No Generalized Position, \
the rule does detect the characteristic in a fixed position and is unlikely to generalize as a result.""",
}


def get_message(code: str) -> str:
    return MESSAGES.get(code[1:], "No message available for this code.")

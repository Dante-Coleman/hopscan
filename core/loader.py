import email
from email import policy

def load_email(path: str):
    #Decide mode based on file extension
    if path.lower().endswith(".eml"):
        with open(path, "rb") as f:
            msg = email.message_from_binary_file(f, policy=policy.default)

    else:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            msg = email.message_from_string(f.read(), policy=policy.default)

    return dict(msg.items())

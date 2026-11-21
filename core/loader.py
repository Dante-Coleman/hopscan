import email
from email import policy
from email.message import Message


def load_email(path: str) -> Message:
    """Load an email from a .eml or .txt file. Bytes are parsed directly so non-UTF-8 mail isn't mangled."""
    with open(path, "rb") as f:
        return email.message_from_binary_file(f, policy=policy.default)

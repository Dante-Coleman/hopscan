"""Static extraction of the message body: text, links, HTML features and attachments. Nothing is fetched or run."""
import io
import re
import zipfile
from email.message import Message
from html.parser import HTMLParser
from typing import List, Optional
from urllib.parse import urlsplit

from .models import Attachment, ContentInfo, Link

_URL = re.compile(r"(?i)\b(?:https?://|www\.)[^\s<>\"'()\[\]{}]+")
_TRAILING = ".,;:!?'\")]}>"
_IGNORED_SCHEMES = ("mailto:", "tel:", "sms:", "cid:", "#")
_ARCHIVE_TYPES = ("application/zip", "application/x-zip-compressed")
MAX_ARCHIVE_MEMBERS = 50


class _HTMLScanner(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.links: List[tuple] = []  # (source, url, text)
        self.text: List[str] = []
        self.has_form = self.has_password = self.has_script = self.has_meta_refresh = False
        self._href: Optional[str] = None
        self._link_text: List[str] = []
        self._skip = 0  # Inside <script> or <style>.

    def handle_starttag(self, tag, attrs):
        a = {k.lower(): (v or "") for k, v in attrs}
        if tag == "a" and a.get("href"):
            self._href, self._link_text = a["href"].strip(), []
        elif tag == "form":
            self.has_form = True
            if a.get("action"):
                self.links.append(("form", a["action"].strip(), ""))
        elif tag == "input" and a.get("type", "").lower() == "password":
            self.has_password = True
        elif tag == "script":
            self.has_script = True
            self._skip += 1
        elif tag == "style":
            self._skip += 1
        elif tag == "meta" and a.get("http-equiv", "").lower() == "refresh":
            self.has_meta_refresh = True
            m = re.search(r"url\s*=\s*['\"]?([^'\";\s]+)", a.get("content", ""), re.I)
            if m:
                self.links.append(("meta-refresh", m.group(1), ""))
        elif tag in ("br", "p", "div", "tr", "li"):
            self.text.append("\n")

    def handle_endtag(self, tag):
        if tag == "a" and self._href is not None:
            self.links.append(("html", self._href, " ".join("".join(self._link_text).split())))
            self._href = None
        elif tag in ("script", "style") and self._skip:
            self._skip -= 1

    def handle_data(self, data):
        if self._skip:
            return
        self.text.append(data)
        if self._href is not None:
            self._link_text.append(data)


def make_link(url: str, text: str = "", source: str = "text") -> Optional[Link]:
    url = url.strip()
    lower = url.lower()
    if not url or lower.startswith(_IGNORED_SCHEMES):
        return None
    if lower.startswith("javascript:") or lower.startswith("data:"):
        return Link(url=url[:200], host=None, text=text, source=source)
    if lower.startswith("www."):
        url = "http://" + url
    if not re.match(r"(?i)^https?://", url):
        return None  # Relative links and other schemes say nothing about where you'd end up.
    try:
        parts = urlsplit(url)
        host = parts.hostname
    except ValueError:
        return None
    return Link(url=url, host=host.rstrip(".") if host else None, text=text, source=source,
                has_userinfo="@" in parts.netloc)


def _part_text(part: Message) -> str:
    try:
        return part.get_content()
    except Exception:  # Unknown charset or broken encoding.
        payload = part.get_payload(decode=True) or b""
        return payload.decode("utf-8", errors="replace")


def _inspect_archive(attachment: Attachment, payload: bytes) -> None:
    try:
        with zipfile.ZipFile(io.BytesIO(payload)) as z:
            infos = z.infolist()
    except (zipfile.BadZipFile, ValueError, OSError):
        return
    attachment.archive_members = [i.filename for i in infos[:MAX_ARCHIVE_MEMBERS]]
    attachment.encrypted = any(i.flag_bits & 0x1 for i in infos)


def extract_content(msg: Message) -> ContentInfo:
    info = ContentInfo()
    texts: List[str] = []
    seen_urls = set()

    def add_link(link: Optional[Link]):
        if link and (link.url, link.text, link.source) not in seen_urls:
            seen_urls.add((link.url, link.text, link.source))
            info.links.append(link)

    for part in msg.walk():
        if part.is_multipart():
            continue
        ctype = part.get_content_type()
        filename = part.get_filename()
        if filename or part.get_content_disposition() == "attachment":
            payload = part.get_payload(decode=True) or b""
            att = Attachment(filename=filename or "(unnamed)", content_type=ctype, size=len(payload))
            if ctype in _ARCHIVE_TYPES or att.filename.lower().endswith(".zip"):
                _inspect_archive(att, payload)
            info.attachments.append(att)
        elif ctype == "text/plain":
            body = _part_text(part)
            texts.append(body)
            for m in _URL.finditer(body):
                add_link(make_link(m.group(0).rstrip(_TRAILING)))
        elif ctype == "text/html":
            scanner = _HTMLScanner()
            try:
                scanner.feed(_part_text(part))
                scanner.close()
            except Exception:
                pass
            for source, url, text in scanner.links:
                if url.lower().startswith("javascript:"):
                    scanner.has_script = True
                add_link(make_link(url, text, source))
            info.has_form |= scanner.has_form
            info.has_password_field |= scanner.has_password
            info.has_script |= scanner.has_script
            info.has_meta_refresh |= scanner.has_meta_refresh
            texts.append("".join(scanner.text))

    info.text = "\n".join(t.strip() for t in texts if t.strip())
    return info

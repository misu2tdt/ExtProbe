"""v3.1-probe click policy (pure Python: no browser; unit-tested in tests/v31).

  ext_pages(manifest)   pages to explore, from the manifest (popup first, then options)
  skip_reason(item)     why an element is never clicked (deny, login, external, select, unlabeled, non_english)
                        or None
  priority(item)        click priority of an element (lower = earlier), or None = never clicked
  login_gate(snapshot)  True when a page asks to log in / sign up and offers nothing else to switch on
  state_hash(snapshot)  hash of the visible interactive state (for the BFS)
Deny and login words match as word PREFIXES ("delete" also matches "Deleting", "report" matches "Reports",
"payment" matches "Payments"); priority words match whole words ("on" does not match "online"). An element
without a label (no letter in it) or whose label has letters outside ASCII (taken as not English) is never
clicked: the deny list cannot be checked on it.
Values typed into forms are the harness honeypot values with a PROBE tag, so that a later analysis can tell
them from the honeypot pages' own values (score_v31.py strips them from the filtered view).
"""
import hashlib
import json
import re

PRIORITY = ["connect", "start", "enable", "activate", "protect", "turn on", "on", "continue", "next", "accept",
            "allow", "scan", "apply", "save", "ok", "get started", "agree", "unlock", "boost", "secure"]
DENY = ["uninstall", "remove", "delete", "clear", "reset", "erase", "buy", "purchase", "pay", "checkout", "upgrade",
        "premium", "subscribe", "unsubscribe", "subscription", "pricing", "price", "plan", "billing", "log out",
        "logout", "log off", "logoff", "sign out", "signout", "sign off", "signoff", "report", "share", "rate",
        "review", "feedback", "donate", "contact", "support", "privacy", "terms", "disclaimer", "faq", "help",
        "learn more", "about", "tutorial", "website"]
LOGIN_WORDS = ["log in", "login", "sign in", "signin", "sign up", "signup", "register", "create account",
               "create an account", "continue with google", "sign in with google", "continue with apple"]
PROBE_EMAIL = "honeyuser-probe@example.com"
PROBE_PASSWORD = "HONEYPOT-PROBE-PW"
PROBE_TOKENS = [PROBE_PASSWORD, "honeyuser-probe"]
FORM_VALUES = {"email": PROBE_EMAIL, "password": PROBE_PASSWORD, "text": "honeyuser-probe", "tel": "0000000000",
               "search": "honeyuser-probe", "url": "https://example.com/", "number": "1"}


def _words(text):
    return (text or "").lower()


def _has(text, words):
    """Whole-word match (priority words)."""
    t = _words(text)
    return any(re.search(r"(?<![a-z])" + re.escape(w) + r"(?![a-z])", t) for w in words)


def _has_prefix(text, words):
    """Word-prefix match (deny / login words): also plurals and inflections ("payments", "deleting"); a final
    "e" of a word of 5+ letters is dropped from the prefix ("delete" -> "delet" matches "deleting")."""
    t = _words(text)
    stems = [w[:-1] if len(w) >= 5 and w.endswith("e") else w for w in words]
    return any(re.search(r"(?<![a-z])" + re.escape(w).replace(r"\ ", r"[\s_-]*"), t) for w in stems)


def skip_reason(item):
    """None = may be clicked; else the reason it never is."""
    text = item.get("text") or ""
    letters = [c for c in text if c.isalpha()]
    if not letters:
        return "unlabeled"
    if any(ord(c) > 127 for c in letters):
        return "non_english"
    if _has_prefix(text, DENY):
        return "deny"
    if _has_prefix(text, LOGIN_WORDS):
        return "login"                                # login gates are recorded, not passed
    if re.match(r"(?i)\s*(https?:|mailto:|tel:)", item.get("href") or ""):
        return "external"                             # leaves the extension: would only open a web tab
    if item.get("tag") == "select":
        return "select"
    return None


def ext_pages(manifest):
    """[(kind, path)] from action / browser_action default_popup and options_page / options_ui.page."""
    pages = []
    act = (manifest or {}).get("action") or (manifest or {}).get("browser_action") or {}
    pop = act.get("default_popup") if isinstance(act, dict) else None
    if isinstance(pop, str) and pop.strip():
        pages.append(("popup", pop.strip().lstrip("/")))
    opt = (manifest or {}).get("options_page") or ((manifest or {}).get("options_ui") or {}).get("page")
    if isinstance(opt, str) and opt.strip() and opt.strip().lstrip("/") not in [p for _, p in pages]:
        pages.append(("options", opt.strip().lstrip("/")))
    return pages


def priority(item):
    """None = never clicked (skip_reason); else lower clicks first."""
    if skip_reason(item):
        return None
    text = item.get("text") or ""
    for k, w in enumerate(PRIORITY):
        if _has(text, [w]):
            return k
    if item.get("role") == "switch" or item.get("type") == "checkbox":
        return len(PRIORITY)
    return len(PRIORITY) + 1


def login_gate(snapshot):
    """A page that asks for an account: a password field or a log-in / sign-up control, and no element whose
    label is in PRIORITY (nothing to switch on without an account)."""
    items = snapshot.get("items") or []
    asks = bool(snapshot.get("password_inputs")) or any(_has_prefix(i.get("text"), LOGIN_WORDS) for i in items)
    switch = any((p := priority(i)) is not None and p < len(PRIORITY) for i in items)
    return asks and not switch


def state_hash(snapshot):
    key = json.dumps([[i.get("tag"), i.get("text"), bool(i.get("checked"))] for i in snapshot.get("items") or []]
                     + [snapshot.get("title"), (snapshot.get("textLen") or 0) // 50])
    return hashlib.sha1(key.encode()).hexdigest()[:12]

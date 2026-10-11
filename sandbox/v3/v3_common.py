"""Shared helpers of the v3 profile (no Playwright / CDP imports: unit-testable on the host)."""
import base64
import hashlib
import time

MAX_BODY_LEN_V3 = 65536          # T1-7: keep request bodies up to 64 kB


def now_ms():
    """Absolute timestamp (epoch milliseconds) for every v3 event (T1-6)."""
    return round(time.time() * 1000, 1)


def body_fields(body):
    """T1-7: fields for a request body given as str or bytes. The hash and the length are of
    the full body; post_data keeps the first MAX_BODY_LEN_V3 characters."""
    if body is None:
        return {}
    raw = body if isinstance(body, (bytes, bytearray)) else str(body).encode("utf-8", "surrogatepass")
    text = body.decode("utf-8", "replace") if isinstance(body, (bytes, bytearray)) else str(body)
    if not raw:
        return {}
    return {
        "post_data": text[:MAX_BODY_LEN_V3],
        "post_data_len": len(text),
        "post_data_bytes": len(raw),
        "post_data_sha256": hashlib.sha256(raw).hexdigest(),
        "post_data_truncated": len(text) > MAX_BODY_LEN_V3,
    }


TEXT_TYPES = ("text/", "application/json", "application/javascript", "application/x-javascript",
              "application/xml", "application/x-www-form-urlencoded", "+json", "+xml")


def response_fields(body, base64_encoded, content_type):
    """A3 / T1-8: response body fields. Text bodies keep the first 64 kB as text; others keep
    the first 64 kB of their base64. Hash and length are of the full decoded body."""
    if body is None:
        return {}
    try:
        raw = base64.b64decode(body) if base64_encoded else str(body).encode("utf-8", "surrogatepass")
    except Exception:
        raw = str(body).encode("utf-8", "replace")
    ct = (content_type or "").lower()
    is_text = any(t in ct for t in TEXT_TYPES)
    out = {"response_body_len": len(raw), "response_body_sha256": hashlib.sha256(raw).hexdigest()}
    if is_text or not base64_encoded:
        text = raw.decode("utf-8", "replace")
        out.update(response_body=text[:MAX_BODY_LEN_V3], response_body_truncated=len(text) > MAX_BODY_LEN_V3)
    else:
        b64 = base64.b64encode(raw).decode()
        out.update(response_body_base64=b64[:MAX_BODY_LEN_V3], response_body_truncated=len(b64) > MAX_BODY_LEN_V3)
    return out


def stack_frames(initiator):
    """All call-frame URLs of a CDP initiator, synchronous then async parents (T1-1)."""
    urls = []
    if initiator.get("url"):
        urls.append(initiator["url"])
    st, hops = initiator.get("stack"), 0
    while st and hops < 64:
        for cf in st.get("callFrames", []):
            if cf.get("url"):
                urls.append(cf["url"])
        st = st.get("parent")
        hops += 1
    return urls


def root_frame(initiator):
    """URL of the outermost caller: the last frame of the last (oldest async) stack segment
    that has frames; the initiator URL when there is no stack."""
    st, hops, last = (initiator or {}).get("stack"), 0, None
    while st and hops < 64:
        urls = [cf.get("url") for cf in st.get("callFrames", []) if cf.get("url")]
        if urls:
            last = urls[-1]
        st = st.get("parent")
        hops += 1
    return last or (initiator or {}).get("url") or None


def attribute(initiator):
    """(label, [extension frame URLs]) for one page request:
      extension                the outermost caller is extension code (content script, injected
                               extension script, extension page)
      page_via_extension_hook  extension frames are on the stack but the outermost caller is the
                               page: the page's own call passed through a wrapper the extension
                               installed in the main world (e.g. a patched fetch / XMLHttpRequest)
      page                     no extension frame
      unknown                  no stack and no initiator URL (browser-initiated, e.g. navigation)"""
    frames = stack_frames(initiator or {})
    ext = list(dict.fromkeys(u for u in frames if u.startswith("chrome-extension://")))[:5]
    root = root_frame(initiator)
    if ext:
        if root and not root.startswith("chrome-extension://"):
            return "page_via_extension_hook", ext
        return "extension", ext
    itype = (initiator or {}).get("type")
    if itype in ("parser", "script", "preload", "preflight", "SignedExchange") or frames:
        return "page", []
    return "unknown", []

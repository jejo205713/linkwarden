"""Stub heavyweight / OS-bound deps so unit tests run on any environment.

`whois`, `Levenshtein`, and `tldextract` are imported eagerly by backend
modules. Tests don't exercise them — they only need the module surface to
exist. Patch sys.modules before any test imports the backend.
"""
import sys
import types
from urllib.parse import urlparse


if "whois" not in sys.modules:
    fake_whois = types.ModuleType("whois")
    fake_whois.whois = lambda domain: types.SimpleNamespace(creation_date=None, registrar=None)
    sys.modules["whois"] = fake_whois


try:
    import Levenshtein  # noqa: F401  -- prefer the real module if installed
except ImportError:
    fake_lev = types.ModuleType("Levenshtein")

    def _levenshtein_distance(a, b):
        if a == b:
            return 0
        if not a:
            return len(b)
        if not b:
            return len(a)
        prev = list(range(len(b) + 1))
        for i, ca in enumerate(a, 1):
            curr = [i]
            for j, cb in enumerate(b, 1):
                ins = curr[j - 1] + 1
                dele = prev[j] + 1
                sub = prev[j - 1] + (0 if ca == cb else 1)
                curr.append(min(ins, dele, sub))
            prev = curr
        return prev[-1]

    def _ratio(a, b):
        if not a and not b:
            return 1.0
        d = _levenshtein_distance(a, b)
        return (len(a) + len(b) - d) / (len(a) + len(b))

    fake_lev.ratio = _ratio
    sys.modules["Levenshtein"] = fake_lev


# tldextract may be installed without its TLD snapshot file. Stub a minimal
# replacement that returns plausible domain/suffix splits for test inputs.
def _build_tldextract_stub():
    mod = types.ModuleType("tldextract")

    class _Result:
        __slots__ = ("subdomain", "domain", "suffix")

        def __init__(self, subdomain, domain, suffix):
            self.subdomain = subdomain
            self.domain = domain
            self.suffix = suffix

    _COMPOUND_SUFFIXES = ("co.in", "co.uk", "com.au", "co.jp", "ac.in", "gov.in", "org.in")
    _SIMPLE_SUFFIXES = (
        "com", "org", "net", "io", "ai", "in", "xyz", "top", "click",
        "gq", "tk", "cfd", "buzz", "co", "gov", "edu",
    )

    def _split(host):
        parts = host.split(".")
        for compound in _COMPOUND_SUFFIXES:
            comp_parts = compound.split(".")
            if len(parts) >= len(comp_parts) + 1 and parts[-len(comp_parts):] == comp_parts:
                domain = parts[-len(comp_parts) - 1]
                subdomain = ".".join(parts[: -len(comp_parts) - 1])
                return subdomain, domain, compound
        if len(parts) >= 2 and parts[-1] in _SIMPLE_SUFFIXES:
            return ".".join(parts[:-2]), parts[-2], parts[-1]
        if len(parts) >= 2:
            return ".".join(parts[:-2]), parts[-2], parts[-1]
        if len(parts) == 1:
            return "", parts[0], ""
        return "", "", ""

    def _normalize(value):
        try:
            host = urlparse(value).netloc.lower()
        except (ValueError, TypeError):
            host = ""
        if not host:
            host = (value or "").lower()
        host = host.split("@")[-1].split(":")[0]
        return host.lstrip(".")

    def extract(value):
        return _Result(*_split(_normalize(value)))

    class TLDExtract:
        def __init__(self, *args, **kwargs):
            pass

        def __call__(self, value):
            return extract(value)

    mod.extract = extract
    mod.TLDExtract = TLDExtract
    return mod


sys.modules["tldextract"] = _build_tldextract_stub()

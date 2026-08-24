# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""Grounding (fabrication) check for LLM analysis output.

A local model can produce fluent, well-structured analysis that invents IOCs
(observed with qwen3:32b on the RE spike: a fabricated C2 domain + registry
GUID). This module cross-references every concrete IOC value the model claims
against the source input it was given. A value whose concrete artifacts do not
appear in the source (after defang normalization) is a fabrication flag.

Scope: the automated pass grounds `code_level_ioc` values only — the concrete,
fabricable strings (domains, IPs, URLs, registry keys, mutexes). Capabilities
and MITRE techniques are abstractions that rarely appear literally in source;
those are left to the human read in the scorecard.

WHAT THIS METRIC IS FOR, because it decides every judgement call below: it
answers "did the model make this up?", NOT "did the model write it the way we
expected?". Twice now the implementation has drifted into measuring the second
question and reporting the answer as if it were the first.
"""
import re

_REFANG = [
    ("hxxps", "https"),
    ("hxxp", "http"),
    ("[.]", "."),
    ("(dot)", "."),
    ("[:]", ":"),
    ("[@]", "@"),
]


def refang(text: str) -> str:
    """Undo common IOC obfuscation WITHOUT lowercasing.

    Separated from `normalize` because literal extraction must run on refanged text
    (`evil[.]com` matches no artifact pattern; `evil.com` matches the dotted-artifact
    one) while still needing original case (the CamelCase pattern that recognises
    `CheckRemoteDebuggerPresent` cannot survive lowercasing). Extracting from raw text
    silently dropped every defanged domain — the single most fabricable IOC there is.
    """
    out = text or ""
    for fanged, plain in _REFANG:
        out = out.replace(fanged, plain)
    return out


def normalize(text: str) -> str:
    """Lowercase, refang common IOC obfuscations, and collapse whitespace."""
    return re.sub(r"\s+", " ", refang((text or "").lower())).strip()


def _ioc_value(ioc: object) -> str:
    """Pull the claim string out of an IOC entry, whatever shape the model used.

    Models do not agree on the schema: claude-sonnet-5 emits dicts
    ({"type","value","context"}), qwen3.6 emits bare strings. Assuming dicts
    raised AttributeError: 'str' object has no attribute 'get' and killed 5 of 7
    local cells mid-scoring on 2026-07-25 — after their results were written, so
    the run looked like "0 claims, 28% completion" rather than a crash.
    """
    if isinstance(ioc, dict):
        return str(ioc.get("value", "")).strip()
    if isinstance(ioc, str):
        return ioc.strip()
    return str(ioc).strip()


# Literal artifacts embedded inside a descriptive claim.
#
# The first four patterns match DELIMITED or PREFIXED evidence. On their own they
# encode one model's citation habits as the definition of a checkable claim:
# claude-sonnet-5 backticks and quotes its artifacts, qwen3.6 writes them bare. On
# 2026-07-29 that scored a raccoonstealer run at 1/4 grounded when all four claims
# were verbatim in the tool output — the mutex `MilcoSoft_#Rip_X` appeared twice,
# `CheckRemoteDebuggerPresent` 123 times. The only claim that scored was the one
# whose evidence happened to look like a Ghidra symbol.
#
# The last three match BARE evidence. Each requires enough structure to be an
# artifact rather than an English word:
#   - hex runs of 8+ chars (a decrypted-string sample, a hash fragment)
#   - identifiers containing _ or # (mutex and event names, snake_case symbols)
#   - CamelCase with 2+ humps (Win32 API names: DestroyWindow, GetObjectW)
# Ordinary prose does not match these. "Repeated" has no second hump; "Anti-Debug"
# splits on the hyphen.
_LITERAL_PATTERNS = (
    re.compile(r"`([^`]{2,})`"),
    re.compile(r'"([^"]{2,})"'),
    re.compile(r"\b(0x[0-9a-fA-F]{2,})\b"),
    re.compile(r"\b((?:FUN|DAT|LAB|SUB)_[0-9a-fA-F]{4,})\b"),
    re.compile(r"\b([0-9a-fA-F]{8,})\b"),
    # NOTE the separator run `[_#]+` and the body `[A-Za-z0-9]+` are DISJOINT. An
    # earlier version had `#` in both (`[_#][A-Za-z0-9#]+`), so a run of `##` could be
    # split between them many ways -- CodeQL py/redos, high severity, and a genuine
    # availability bug here: this scorer parses model output derived from malware, so a
    # crafted IOC string could hang the eval harness. Disjoint classes make the match
    # unambiguous and linear.
    re.compile(r"\b([A-Za-z][A-Za-z0-9]*(?:[_#]+[A-Za-z0-9]+)+)\b"),
    re.compile(r"\b([A-Z][a-z0-9]+(?:[A-Z][a-z0-9]*)+)\b"),
    # Dotted artifacts: domains, IPv4, filenames. These are THE canonical fabricable
    # IOC — the module exists because qwen3:32b invented a C2 domain — and an early
    # draft of #243 missed them entirely, which would have moved invented domains from
    # `fabricated` to `unscoreable` and quietly disarmed the check. Ordinary prose does
    # not survive the 4-character floor ("e.g", "i.e", "1.0"), and "do..while" has no
    # label between its dots.
    re.compile(r"\b([A-Za-z0-9][A-Za-z0-9~%_-]*(?:\.[A-Za-z0-9~%_-]+)+)\b"),
    re.compile(r"(https?://[^\s\"'<>,)\]]+)"),
    re.compile(r"((?:[A-Za-z]:\\\\?|\\\\\\\\|HKEY_[A-Z_]+\\\\?)[^\s\"',)\]]+)"),
)

# Cap on literals checked per claim. Generous, and truncation is REPORTED rather
# than silent — the previous limit of 6 meant a claim citing ten artifacts had four
# never checked, with nothing in the output to say so.
_LITERAL_LIMIT = 12


def _extract_literals(value: str, limit: int = _LITERAL_LIMIT) -> list[str]:
    """Pull checkable literals out of a prose IOC claim.

    THE SHARED CONTRACT. `lamware_eval.consensus` matches claims across seeded runs
    using exactly these literals, so this returns a plain list and must keep doing so.
    An earlier draft of #243 changed it to a (list, truncated) tuple for the scorer's
    benefit and broke consensus with an AttributeError at a distance. Callers wanting
    the truncation flag use `_extract_literals_detail`.
    """
    return _extract_literals_detail(value, limit)[0]


def _extract_literals_detail(value: str, limit: int = _LITERAL_LIMIT) -> tuple[list[str], bool]:
    """As `_extract_literals`, plus whether the limit truncated the result.

    Models format IOCs very differently: claude-sonnet-5 emits bare artifacts
    ("~%u.tmp", "0x811c9dc5"), qwen3.6 emits descriptive signatures such as
    "XOR pattern `data[i] ^ key[i % len]` in a do..while loop in `FUN_0040b477`"
    or "Mutex/Event Name: MilcoSoft_#Rip_X". A whole sentence never appears
    verbatim in decompilation, so substring matching scored EVERY descriptive
    claim as fabricated — on 2026-07-25 that put the local arm at 0/20 grounded,
    including `FUN_0040b477`, an address four independent runs had corroborated.

    Grounding the literals inside the description scores every style fairly.
    """
    out: list[str] = []
    seen: set[str] = set()
    # Refang FIRST, keeping case: `evil[.]com` matches no pattern, `evil.com` does.
    value = refang(value)
    # Taxonomy labels are dropped before extraction, not after, so they cannot reach
    # `seen` and mask a later identical token that IS evidence.
    type_labels = {m.lower() for m in _TYPE_LABEL.findall(value)}
    for pat in _LITERAL_PATTERNS:
        for m in pat.findall(value):
            tok = m.strip()
            key = tok.lower()
            # Skip fragments too short or too generic to be evidence.
            if len(tok) < 4 or key in seen:
                continue
            # Wildcard symbols name a family, not an artifact — see _PLACEHOLDER_SYMBOL.
            if _PLACEHOLDER_SYMBOL.match(tok):
                continue
            # A `type:` value is the model's category for the evidence, not evidence.
            if key in type_labels:
                continue
            if len(out) >= limit:
                return _drop_subsumed(out), True
            seen.add(key)
            out.append(tok)
    return _drop_subsumed(out), False


def _drop_subsumed(literals: list[str]) -> list[str]:
    """Remove literals wholly contained in another literal from the same claim.

    The patterns overlap by design: `MilcoSoft.dll` matches both the CamelCase rule
    (`MilcoSoft`) and the dotted-artifact rule (`MilcoSoft.dll`), and `FUN_0040b477`
    also yields the bare hex run `0040b477`. Keeping both halves is redundant for
    grounding and actively wrong for `lamware_eval.consensus`, which keys claims on
    these literals: one artifact produced two keys, so a single claim agreed by two
    runs was reported as two separate agreements.

    Keeps the longest form, which is the most specific and the least likely to
    collide with unrelated text.
    """
    kept: list[str] = []
    for lit in sorted(literals, key=len, reverse=True):
        low = lit.lower()
        if not any(low in k.lower() for k in kept):
            kept.append(lit)
    # Restore the original discovery order so output stays stable and readable.
    return [lit for lit in literals if lit in kept]


# Hex addresses are the one literal class whose spelling varies WITHIN a single
# tool's output. Ghidra prints zero-padded addresses in string listings
# (`0x00419070`) and bare ones in decompiled operands (`0x41970c`), so a model that
# faithfully quotes the listing form for an address that appears in code is scored as
# having invented it.
#
# Measured 2026-08-03 (qwen@15:s1337, raccoonstealer). The claim
#   "XOR Key Pattern: hex strings in data section (0x00419070-0x0041970c) are
#    16-byte XOR-encoded API names"
# was flagged fabricated on the single literal `0x0041970c`, while the source held
#   pCVar1 = FUN_0040b477(0x41970c,"23ff5473b825af32",0x18);
#   DAT_0041c094 = GetProcAddress(pHVar2,pCVar1);
# — the same address, feeding a decode helper into GetProcAddress. The claim was not
# merely grounded but correct, and it was the run's only "fabrication".
#
# This is the same failure this module already carries a scar for: substring matching
# once scored every DESCRIPTIVE claim as fabricated (0/20 on 2026-07-25). That was
# fixed by extracting literals; this is the narrower form, one layer down, where the
# literal itself is re-spelled.
#
# Matching by VALUE rather than by spelling. Boundary-anchored in both directions so
# the fix cannot widen into a loophole: a shorter address must not be satisfied by a
# longer one that merely contains it (`0x4197` is NOT grounded by `0x41970c`), which
# plain substring matching would have allowed and still would.
#
# THE PREFIX IS NOT PART OF THE VALUE EITHER. The first version of this required a
# literal `0x` in the SOURCE, which fixed the padding case and missed the commoner
# one — Ghidra names an address as a SYMBOL far more often than it prints it as a
# number:
#
#   claim:  "Encrypted Payload at 0x140054300"
#   source: DAT_140054300
#
# Measured 2026-08-04 on the qwen@15 six-sample sweep: NINE of amadey's eleven
# "fabrications" were this, dropping that cell to 2/13 = 0.154 when the true score is
# 11/13 = 0.846, and the sweep mean from 0.655 to 0.516. Every address was in the
# source, several of them four times over.
#
# So the address is matched with an OPTIONAL `0x` and any non-hex-word boundary
# before it, which covers `0x140054300`, `140054300`, `DAT_140054300` and
# `FUN_140054300` alike. Generalising here rather than adding a third special case:
# the property wanted is "this hex value appears in the source", and the surrounding
# syntax is Ghidra's choice, not the model's claim.
#
# A prefix-less match needs >= _MIN_BARE_HEX_DIGITS digits. Without a `0x` to anchor
# on, a short value like `0x40` would collide with any decimal 40 in the tool output
# (a length, a count, an offset) and ground a claim on a coincidence. Real addresses
# in this corpus are 6-12 digits, so the floor costs nothing and closes that hole.
_HEX_LITERAL = re.compile(r"\A0x([0-9a-f]+)\Z")  # \Z: `$` also matches before a trailing newline
_MIN_BARE_HEX_DIGITS = 4


def _hex_value_pattern(literal: str) -> "re.Pattern | None":
    """A source pattern matching `literal`'s VALUE however it is spelled, or None.

    Tolerates zero-padding and an absent `0x`, so a claim citing an address matches
    whether the source wrote it as a number or embedded it in a Ghidra symbol.
    """
    m = _HEX_LITERAL.match(literal)
    if not m:
        return None
    digits = m.group(1).lstrip("0") or "0"
    # `(?<![0-9a-z])` also rejects a match inside a longer hex run, and permits the
    # `_` of DAT_/FUN_ (underscore is outside the class). `(?![0-9a-f])` stops a
    # short value being satisfied by a longer one that merely starts with it.
    prefix = "0x0*" if len(digits) < _MIN_BARE_HEX_DIGITS else "(?:0x)?0*"
    return re.compile(rf"(?<![0-9a-z]){prefix}{digits}(?![0-9a-f])")


# Placeholder notation is a pattern, not an artifact. Models write `DAT_0041cXXX` to
# denote a FAMILY of addresses; the X's are wildcards standing in for digits. Such a
# token can never appear in any source, so the claim scored `fabricated` — recording
# "the model invented this" for what is really "this claim names a pattern".
#
# Measured 2026-08-03: qwen@10:s42's "API Resolution Table: Multiple DAT_0041cXXX
# function pointers" was flagged, though DAT_0041c008, DAT_0041c074 and DAT_0041c094
# are all present in the decompilation.
#
# Dropping the placeholder routes such a claim to `unscoreable`, which is honest
# labelling and — BY DESIGN — scores identically, because unscoreable stays in the
# denominator. This changes what we say about a model, not what we score it.
# Deliberately narrow: only Ghidra symbol prefixes with a trailing run of X's, so it
# cannot be used to launder a real fabrication into an unscoreable one.
_PLACEHOLDER_SYMBOL = re.compile(r"\A(?:FUN|DAT|LAB|PTR|SUB|UNK)_[0-9a-fA-F]*X{2,}\Z")

# A `type:` field names the KIND of evidence. It is not evidence.
#
# When the model fills the schema directly it often writes structured claims:
#
#     type: magic_value, value: 0x2b992ddfa232, context: Anti-sandbox check in FUN_...
#
# `magic_value` contains an underscore, so the identifier rule above — written for
# mutex and event names like `MilcoSoft_#Rip_X` — captures it as an artifact. It then
# cannot be found in any decompilation, because it is the model's own taxonomy
# vocabulary, and the whole claim is scored as a fabrication.
#
# Measured 2026-08-05 on qwen@15 / warmcookie after #298 moved synthesis to a single
# forced tool call: THREE of four claims flagged, dropping the cell to 1/4 = 0.250 when
# every hex value and function name in them was present. Corrected score 4/4 = 1.000.
# The format change came from #298, so this would have contaminated every before/after
# comparison of that change — a scoring artifact masquerading as a regression.
#
# Narrow by construction: only the value of an explicit `type:`/`kind:`/`category:`
# key is dropped, and only that token. Everything else in the claim — the hex value,
# the function name, the context prose — is extracted and checked exactly as before.
_TYPE_LABEL = re.compile(r"\b(?:type|kind|category)\s*:\s*([A-Za-z][A-Za-z0-9_#]*)",
                         re.IGNORECASE)


def _literal_in_source(literal: str, norm_source: str) -> bool:
    """True when `literal` is attested by `norm_source`, allowing hex re-spelling."""
    norm = normalize(literal)
    pattern = _hex_value_pattern(norm)
    if pattern is not None:
        return pattern.search(norm_source) is not None
    return norm in norm_source


# Auto-generated Ghidra symbol names. A claim consisting of NOTHING BUT one of these
# is contentless: it scores as grounded because appearing in the decompilation is what
# makes it a symbol name in the first place.
#
# Measured 2026-08-07, raccoonstealer, qwen@15: 12 of 17 code_level_iocs were bare
# `DAT_` addresses. It scored 16/17 = 0.941 and looked 3.4x more productive than
# qwen@10's 5/5 = 1.000 — which had named the same findings WITH their significance
# ("Magic constant 0x5cdabf15 used in GetObjectW parameter in anti-analysis routine").
# The metric rewarded enumeration over explanation, which is #225's hypothesis.
#
# `FUN_0041246b is the core anti-analysis function` is NOT bare — the symbol carries a
# claim about it. Only a value that is the symbol ALONE qualifies.
_BARE_SYMBOL = re.compile(r"\A(?:DAT|FUN|LAB|SUB|UNK|PTR)_[0-9A-Fa-f]+\Z", re.IGNORECASE)

# Constants whose identity is unambiguous, for detecting a REAL value with a FABRICATED
# explanation — a class grounding structurally cannot see, because the literal is
# genuinely in the source and only the interpretation is wrong.
#
# Measured 2026-08-07, icedid: qwen@10 said "0x811c9dc5 used in FNV-1a hash validation
# routine" (correct); qwen@15 said "Adler-32 initial value: 0x811c9dc5" (wrong). Both
# scored grounded. Depth 15 REGRESSED and the scorecard showed it as an improvement.
#
# Every entry must be a mapping nobody disputes. A table that guesses is worse than no
# table: a false `misattributed` would discredit the check that catches the real ones.
_KNOWN_CONSTANTS: dict[str, tuple[str, frozenset[str]]] = {
    "811c9dc5": ("FNV-1a 32-bit offset basis", frozenset({"fnv"})),
    "1000193": ("FNV-1a 32-bit prime", frozenset({"fnv"})),
    "cbf29ce484222325": ("FNV-1a 64-bit offset basis", frozenset({"fnv"})),
    "100000001b3": ("FNV-1a 64-bit prime", frozenset({"fnv"})),
    "edb88320": ("CRC-32 reversed polynomial", frozenset({"crc"})),
    "4c11db7": ("CRC-32 polynomial", frozenset({"crc"})),
    "5a827999": ("SHA-1 round constant", frozenset({"sha1", "sha-1"})),
    "6a09e667": ("SHA-256 / BLAKE initial value", frozenset({"sha256", "sha-256", "blake"})),
    "9e3779b9": ("TEA/XXTEA delta (golden ratio)", frozenset({"tea", "golden ratio"})),
}

# Algorithm names the checker is willing to call WRONG. Restricted to this vocabulary
# so an unrecognised word is never treated as a contradiction — the check must only
# fire when the claim names a specific algorithm that the table rules out.
_ALGO_VOCAB: dict[str, str] = {
    "fnv": "fnv", "adler-32": "adler", "adler32": "adler", "adler": "adler",
    "crc-32": "crc", "crc32": "crc", "crc": "crc",
    "md5": "md5", "sha-1": "sha1", "sha1": "sha1",
    "sha-256": "sha256", "sha256": "sha256", "blake": "blake",
    "tea": "tea", "xxtea": "tea", "xtea": "tea",
    "aes": "aes", "rc4": "rc4", "des": "des", "murmur": "murmur",
}

# Windows constants checked in the OTHER direction: the claim names the symbol, so the
# value it cites is verifiable. `Memory protection: 0x20 (PAGE_EXECUTE_READWRITE)` was
# the observed instance — 0x20 is PAGE_EXECUTE_READ; READWRITE is 0x40.
_NAMED_CONSTANTS: dict[str, str] = {
    "page_noaccess": "1", "page_readonly": "2", "page_readwrite": "4",
    "page_writecopy": "8", "page_execute": "10", "page_execute_read": "20",
    "page_execute_readwrite": "40", "page_execute_writecopy": "80",
}

_HEX_IN_TEXT = re.compile(r"0x([0-9a-fA-F]+)")

# Separator allowed between a named constant and a value ASSERTED of it. Only
# punctuation, whitespace and a short list of copulas — deliberately not
# arbitrary words, because "at 0x401230 requests PAGE_EXECUTE_READWRITE" states
# an address and a protection, not an equality between them.
_ASSERTS = r"[\s:=,;()\[\]—–-]*(?:is|was|are|were|=|i\.e\.|means)?[\s:=,;()\[\]—–-]*"


def _values_asserted_of(text: str, name: str) -> set[str]:
    """Hex values the text actually claims ARE `name`, normalised like the table.

    Scoped to the constant. This used to collect every hex value anywhere in the
    text and require the constant's value to be among them, so a correct claim
    that happened to mention an address was reported as a misattribution:
    "VirtualAlloc at 0x00401230 requests PAGE_EXECUTE_READWRITE" was flagged as
    "PAGE_EXECUTE_READWRITE is 0x40, not 0x401230". That phrasing — name the
    protection, cite the call site — is how RE prose is normally written, and
    this is the checker that measures hallucination, so the false positives
    landed as invented hallucinations against correct analyses.
    """
    escaped = re.escape(name)
    found: set[str] = set()
    for pattern in (rf"0x([0-9a-fA-F]+){_ASSERTS}{escaped}",     # 0x20 (PAGE_EXECUTE_READ)
                    rf"{escaped}{_ASSERTS}0x([0-9a-fA-F]+)"):    # PAGE_EXECUTE_READ is 0x20
        for raw in re.findall(pattern, text, re.IGNORECASE):
            found.add(raw.lstrip("0").lower() or "0")
    return found


def constant_misattributions(text: str) -> list[str]:
    """Constants in `text` whose stated meaning contradicts a known-unambiguous one.

    Returns a human-readable description per contradiction, empty when the text either
    names the constant correctly or expresses no opinion about it. Silence is the
    default: naming no algorithm is not an error.
    """
    lowered = text.lower()
    named = {term for term in _ALGO_VOCAB
             if re.search(rf"(?<![a-z0-9]){re.escape(term)}(?![a-z0-9])", lowered)}
    families = {_ALGO_VOCAB[t] for t in named}
    out: list[str] = []

    for raw in _HEX_IN_TEXT.findall(text):
        key = raw.lstrip("0").lower() or "0"
        entry = _KNOWN_CONSTANTS.get(key)
        if entry is None:
            continue
        canonical, ok_terms = entry
        ok_families = {_ALGO_VOCAB[t] for t in ok_terms if t in _ALGO_VOCAB}
        if families & ok_families:
            continue  # named correctly
        wrong = families - ok_families
        if wrong:
            out.append(f"0x{raw} is the {canonical}, not {'/'.join(sorted(wrong))}")

    # Longest match only. These names nest — PAGE_EXECUTE is a substring of
    # PAGE_EXECUTE_READWRITE — so matching every occurrence reports the shorter name
    # against the longer one's value and flags correct claims as wrong.
    present = [n for n in _NAMED_CONSTANTS if n in lowered]
    present = [n for n in present
               if not any(n != other and n in other for other in present)]
    for name in present:
        expected = _NAMED_CONSTANTS[name]
        cited = _values_asserted_of(text, name)
        if cited and expected not in cited:
            out.append(f"{name.upper()} is 0x{expected.upper()}, not "
                       f"0x{sorted(cited)[0].upper()}")
    return out


def grounding_scorecard(analysis: dict, source_text: str) -> dict:
    """Score how many claimed code_level_ioc values are supported by the source.

    Every claim lands in exactly one bucket:

      grounded    — every literal it cites appears in the source
      partial     — some cited literals appear, others do not
      fabricated  — it cites literals and NONE of them appear
      unscoreable — no checkable literal could be extracted

    `unscoreable` exists because the previous implementation had no such bucket: a
    claim yielding no literals fell through to `fabricated`, so "I cannot check this"
    was recorded as "the model invented this". Combined with an extractor that only
    recognised delimited evidence, that manufactured a 0.25 grounding score for a run
    in which every claim was true.

    But unscoreable is NOT free. It counts in the denominator as ungrounded, because
    `code_level_ioc` is contractually a list of concrete, checkable artifacts, and
    excluding vague prose would let a model emit one real IOC plus nine sentences of
    hedging and score 1.0. That is the same loophole `partial` closes, and the same one
    `aggregate()` already documents for cells claiming nothing at all. Labelling is
    honest; scoring stays strict.

    `partial` exists because requiring ALL literals made one absent or mis-transcribed
    token condemn an otherwise well-evidenced claim. It is a SUB-CLASSIFICATION, not a
    lighter verdict: partial claims remain in `fabricated` so that extraction can never
    become a free pass — one invented artifact still flags the claim.

    grounded_ratio = grounded / every claim that carried a value. Only `grounded`
    counts in the numerator.
    """
    iocs = analysis.get("code_level_ioc") or analysis.get("code_level_iocs") or []
    norm_source = normalize(source_text)

    grounded = 0
    partial: list[str] = []
    fabricated: list[str] = []
    unscoreable: list[str] = []
    bare_symbols: list[str] = []
    misattributed: list[str] = []
    truncated = 0
    details: list[dict] = []

    for ioc in iocs:
        value = _ioc_value(ioc)
        if not value:
            continue

        # Reported, never silently excluded (#319). These deliberately do NOT change
        # grounded_ratio: altering the headline would make every archived scorecard
        # incomparable, and the point is to make the failure VISIBLE, not to
        # re-baseline by stealth. Whether a bare symbol should count as grounded is a
        # real question — it belongs to a deliberate re-baseline alongside #321, not
        # to the change that first makes it measurable.
        if _BARE_SYMBOL.match(value.strip().strip("`")):
            bare_symbols.append(value)
        wrong = constant_misattributions(value)
        if wrong:
            misattributed.extend(wrong)

        # A claim short enough to appear verbatim is grounded outright.
        if normalize(value) in norm_source:
            grounded += 1
            details.append({"claim": value, "verdict": "grounded", "found": None, "of": None})
            continue

        literals, was_truncated = _extract_literals_detail(value)
        truncated += int(was_truncated)

        if not literals:
            unscoreable.append(value)
            details.append({"claim": value, "verdict": "unscoreable", "found": 0, "of": 0})
            continue

        found = [t for t in literals if _literal_in_source(t, norm_source)]
        detail = {"claim": value, "found": len(found), "of": len(literals),
                  "missing": [t for t in literals if t not in found][:5]}
        if len(found) == len(literals):
            grounded += 1
            detail["verdict"] = "grounded"
        else:
            # Every ungrounded-but-scoreable claim is flagged, whether it cited one
            # invented artifact among several or nothing real at all. `partial` records
            # WHICH, without softening the flag — otherwise extraction becomes a free
            # pass: bury a fabricated domain among four real symbols and score clean.
            fabricated.append(value)
            if found:
                partial.append(value)
            detail["verdict"] = "partial" if found else "fabricated"
        details.append(detail)

    # Unscoreable claims ARE in the denominator: see the docstring. Vague prose in a
    # field defined as concrete artifacts must not be a costless way to pad output.
    total = grounded + len(fabricated) + len(unscoreable)
    ratio = 1.0 if total == 0 else round(grounded / total, 3)
    return {
        # Keys the scorecard has always consumed.
        "total": total,
        "grounded": grounded,
        "fabricated": fabricated,
        "grounded_ratio": ratio,
        # Added by #243.
        "partial": partial,
        "unscoreable": unscoreable,
        "truncated_claims": truncated,
        # Added by #319. Both are ways a claim can score as grounded while being
        # worthless or wrong, and they fail in OPPOSITE directions: bare symbols
        # inflate the score, misattribution hides a regression. Neither is folded
        # into grounded_ratio — see the loop above.
        "bare_symbol_claims": bare_symbols,
        "misattributed": misattributed,
        "details": details,
    }

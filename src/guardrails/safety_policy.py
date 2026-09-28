"""Deterministic checks shared by Blue's input and output boundaries.

These checks deliberately make no claim to recognize every possible language or
harmful instruction. They reject unsupported scripts and clear unsafe intent;
the model instruction remains a separate layer.
"""
from __future__ import annotations

import re
import unicodedata


_VIETNAMESE_MARKS = frozenset("\u0300\u0301\u0303\u0309\u0323\u0302\u0306\u031b")
_FOREIGN_WORDS = frozenset({
    "bonjour", "bonsoir", "merci", "pourquoi", "comment", "quel", "quelle",
    "compte", "bancaire", "solde", "pouvez", "vous", "est", "mon", "une",
    "hola", "gracias", "donde", "cuenta", "bancaria", "saldo", "puedo",
    "quiero", "como", "cual", "por", "favor", "esta", "banco",
    "hallo", "danke", "bitte", "konto", "kontostand", "wie", "kann",
    "mein", "meine", "ist", "und", "ich", "bankkonto",
    "ciao", "grazie", "conto", "bancario", "saldo", "posso",
})
_FOREIGN_UNIQUE = frozenset({
    "bonjour", "bonsoir", "merci", "pourquoi", "pouvez", "bancaire",
    "hola", "gracias", "donde", "cuenta", "bancaria", "quiero",
    "hallo", "danke", "bitte", "konto", "kontostand", "bankkonto",
    "ciao", "grazie", "bancario", "posso",
})
_ENGLISH_WORDS = frozenset({
    "what", "how", "can", "could", "my", "your", "the", "is", "are", "for",
    "with", "account", "bank", "balance", "transfer", "loan", "interest",
    "savings", "card", "help", "please", "explain", "about", "rate",
})
_VIETNAMESE_WORDS = frozenset({
    "toi", "ban", "cua", "la", "bao", "nhieu", "the", "nao", "ngan",
    "hang", "tai", "khoan", "chuyen", "tien", "lai", "suat", "vay",
    "giup", "cho", "duoc", "khong", "va", "co", "tiet", "kiem",
})


def fold(text: str) -> str:
    """Normalize spacing/accents for policy matching, retaining word breaks."""
    text = unicodedata.normalize("NFKC", text or "")
    text = "".join(c for c in text if unicodedata.category(c) != "Cf")
    text = unicodedata.normalize("NFKD", text).casefold()
    return "".join(c for c in text if not unicodedata.combining(c)).replace("đ", "d")


def supported_language(text: str) -> bool:
    """Conservative EN/VI gate; reject unsupported scripts and clear foreign prose.

    Short Latin names and bank/product terms are allowed because their language
    cannot be determined reliably without blocking ordinary customer questions.
    """
    if not isinstance(text, str) or not text.strip():
        return False
    for char in unicodedata.normalize("NFKC", text):
        category = unicodedata.category(char)
        if category.startswith("L") or category.startswith("M"):
            decomposed = unicodedata.normalize("NFD", char)
            if not decomposed or decomposed[0] not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZĐđ":
                return False
            if any(mark not in _VIETNAMESE_MARKS for mark in decomposed[1:]):
                return False
    words = re.findall(r"[a-z]+", fold(text))
    foreign = sum(word in _FOREIGN_WORDS for word in words)
    recognized = sum(word in _ENGLISH_WORDS or word in _VIETNAMESE_WORDS for word in words)
    if any(word in _FOREIGN_UNIQUE for word in words) and foreign >= recognized:
        return False
    return not (len(words) >= 4 and foreign >= 2 and foreign > recognized)


_DANGEROUS = tuple(re.compile(pattern, re.IGNORECASE | re.DOTALL) for pattern in (
    r"\b(?:steal|phish|scam|defraud|launder|forge|counterfeit)\b.{0,80}\b(?:bank|account|card|money|payment|identity|customer|otp|pin|credential)",
    r"\b(?:hack|breach|compromise|exploit|break\s+into|take\s+over)\b.{0,80}\b(?:bank|account|system|customer|card|atm)",
    r"\b(?:bypass|disable|evade|circumvent)\b.{0,60}\b(?:otp|2fa|mfa|authentication|fraud\s+check|security|guardrail|safety|verification)",
    r"\b(?:make|build|write|create|generate|deploy)\b.{0,45}\b(?:malware|ransomware|keylogger|phishing\s+(?:page|email|site)|explosive|bomb|weapon)",
    r"\b(?:send|create|host|build|make)\b.{0,70}\b(?:fake|spoofed|cloned?)\b.{0,25}\b(?:bank|login|payment)",
    r"\b(?:collect|capture|harvest|intercept)\b.{0,55}\b(?:otp|pin|password|credential)",
    r"\b(?:how|steps|instructions|guide|teach|show)\b.{0,45}\b(?:steal|phish|scam|defraud|launder|forge|hack|breach|exploit|bypass\s+(?:otp|2fa|mfa))",
    r"\b(?:reveal|leak|print|copy|export|send|extract|confirm|guess|complete|decode|encode)\b.{0,85}\b(?:admin\s+password|api\s*key|secret|credential|internal\s+(?:note|config|database)|system\s+prompt)",
    r"\b(?:tell|give|show|provide|what\s+is|where\s+is)\b.{0,85}\b(?:admin\s+password|api\s*key|secret|credential|internal\s+(?:note|config|database)|system\s+prompt)",
    r"\b(?:password|api\s*key|secret|credential|internal\s+(?:note|config|database)|system\s+prompt)\b.{0,85}\b(?:reveal|leak|print|copy|export|send|extract|confirm|guess|complete|decode|encode)",
    r"\b(?:decode|decrypt|deobfuscate)\b.{0,60}\b(?:then|and)\b.{0,35}\b(?:follow|execute|obey|run)",
    r"\b(?:danh\s+cap|lua\s+dao|gia\s+mao|rua\s+tien|chiem\s+doat|hack|pha\s+khoa)\b.{0,80}\b(?:tai\s+khoan|ngan\s+hang|the|otp|tien|mat\s+khau)",
    r"\b(?:vuot\s+qua|bo\s+qua|vo\s+hieu\s+hoa)\b.{0,55}\b(?:otp|xac\s+thuc|bao\s+mat|kiem\s+tra|guardrail)",
    r"\b(?:thu\s+thap|lay\s+cap|danh\s+cap)\b.{0,55}\b(?:ma\s+otp|ma\s+pin|mat\s+khau|thong\s+tin\s+dang\s+nhap)",
    r"\b(?:tiet\s+lo|dua\s+toi|cho\s+toi|in\s+ra|xac\s+nhan)\b.{0,65}\b(?:mat\s+khau|khoa\s+api|bi\s+mat|cau\s+hinh\s+noi\s+bo|system\s+prompt)",
))


def dangerous_request(text: str) -> bool:
    normalized = fold(text)
    if re.search(r"\b(?:system[ _-]*prompt|developer[ _-]*message|admin[ _-]*password|internal[ _-]*note|api[ _-]*key|db\.vinbank\.internal)\b", normalized):
        return True
    return any(pattern.search(normalized) for pattern in _DANGEROUS)

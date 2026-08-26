"""BƯỚC 3a — PII gate TRƯỚC KHI vào context/store (12').

Đọc Guide.md (§3a) trước khi bắt đầu: Presidio không có tiếng Việt
sẵn (AnalyzerEngine() mặc định chỉ hỗ trợ "en"). Đường an toàn cho 2h là
regex recognizer + deny-list cho PERSON — coi spaCy/transformers NER là
stretch goal, KHÔNG bắt buộc.

Interface bắt buộc (tests/test_pii.py gọi trực tiếp 2 hàm này):

    detect(text: str) -> list[dict]
        Mỗi entity: {"type": str, "start": int, "end": int}
        `type` là một trong: "VN_CCCD", "VN_PHONE", "VN_BANK_ACCOUNT", "EMAIL"
        `start`/`end` là offset ký tự trong `text` (offset đầu bao gồm,
        offset cuối KHÔNG bao gồm — giống slice Python text[start:end]).
        Format này khớp với tests/vn_pii_testset.jsonl.

    redact(text: str) -> str
        Trả về `text` sau khi mọi entity từ detect() bị thay bằng
        "[REDACTED_<TYPE>]". Phải xử lý overlap/thứ tự đúng khi có nhiều
        entity (gợi ý: thay từ cuối văn bản về đầu để offset không bị lệch).

Gợi ý định dạng (không bắt buộc đúng regex này, miễn đạt ngưỡng trên test
set ở tests/vn_pii_testset.jsonl):
    VN_CCCD          12 chữ số liên tiếp
    VN_PHONE         0 + 9-10 chữ số, có thể có dấu cách/gạch ngang
    VN_BANK_ACCOUNT  8-16 chữ số liên tiếp, thường đi kèm "STK"/"số tài khoản"
    EMAIL            dạng chuẩn local@domain.tld

Đo bằng: pytest tests/test_pii.py -v -s   (in ra precision/recall)
"""
from __future__ import annotations
import re

def detect(text: str) -> list[dict]:        
    entities: list[dict] = []
    # 1. EMAIL
    for m in re.finditer(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", text):
        entities.append({"type": "EMAIL", "start": m.start(), "end": m.end()})
    # 2. VN_PHONE (0 + 9 chữ số)
    for m in re.finditer(r"\b0\d{9}\b", text):
        entities.append({"type": "VN_PHONE", "start": m.start(), "end": m.end()})
    # 3. VN_BANK_ACCOUNT đi kèm tiền tố "STK" / "số tài khoản"
    stk_spans = set()
    for m in re.finditer(r"(?:STK|số tài khoản|stk)\s+(\d{8,16})\b", text, re.IGNORECASE):
        start, end = m.start(1), m.end(1)
        entities.append({"type": "VN_BANK_ACCOUNT", "start": start, "end": end})
        stk_spans.add((start, end))
    # 4. VN_CCCD (12 chữ số liên tiếp, không phải STK)
    for m in re.finditer(r"\b\d{12}\b", text):
        span = (m.start(), m.end())
        if span not in stk_spans:
            if not any(e["start"] <= m.start() and m.end() <= e["end"] for e in entities):
                entities.append({"type": "VN_CCCD", "start": m.start(), "end": m.end()})
    # 5. VN_BANK_ACCOUNT khác (độ dài 8-16 chữ số, trừ 10 chữ số phone và 12 chữ số CCCD)
    for m in re.finditer(r"\b\d{8,16}\b", text):
        length = m.end() - m.start()
        if length in (10, 12):
            continue
        span = (m.start(), m.end())
        if span not in stk_spans:
            if not any(e["start"] <= m.start() and m.end() <= e["end"] for e in entities):
                entities.append({"type": "VN_BANK_ACCOUNT", "start": m.start(), "end": m.end()})
    entities.sort(key=lambda x: x["start"])
    return entities


def redact(text: str) -> str:
    entities = detect(text)
    # Thay thế ngược từ cuối văn bản về đầu để giữ nguyên offset
    entities.sort(key=lambda x: x["start"], reverse=True)
    res = text
    for e in entities:
        replacement = f"[REDACTED_{e['type']}]"
        res = res[: e["start"]] + replacement + res[e["end"] :]
    return res

"""BƯỚC 3c — trifecta split + egress allowlist (13'). ĐÂY LÀ PHẦN KHÓ NHẤT.

Đọc Guide.md (§3c) trước khi viết code. Tóm tắt yêu cầu:

Tách 1 yêu cầu người dùng thành ít nhất 2 run riêng biệt — KHÔNG run nào
được cầm cả 3 chân của trifecta cùng lúc:

    Run A: gọi search_docs (untrusted content).
           KHÔNG gọi read_customer. KHÔNG gọi http_post.
    Run B: gọi read_customer (private data).
           CHỈ nhận input là TYPED, ĐÃ SANITIZE từ Run A — ví dụ
           list[int] ticket id trích từ TÊN FILE (vd "ticket-007.md" -> 7),
           KHÔNG BAO GIỜ nhận nguyên văn text của document. free text của
           attacker không được đi xa hơn Run A.

Mọi lần gọi tool (allow HAY deny) phải:
  1. Đi qua `agent.policy.check()` TRƯỚC KHI tool thật sự chạy.
  2. Được ghi vào ledger qua `agent.ledger.append()` — cả khi deny.
Nếu policy deny, KHÔNG được gọi tool đó.

--- Gợi ý kiến trúc (không bắt buộc theo đúng, nhưng đủ để làm trong 13') ---

data/customers.json có field `related_tickets: list[int]` cho mỗi khách
hàng — đây là NGUỒN TIN CẬY để map ticket_id -> customer_id, KHÔNG map qua
customer_id mà attacker nhúng trong nội dung document. Cụ thể:

    Run A: search_docs(message) -> lấy list[int] ticket_id từ TÊN FILE của
           các doc khớp (vd "ticket-999.md" -> 999). Cũng chạy
           llm.find_injection() trên text để log lại (KHÔNG dùng
           customer_id mà nó trả về).
    Run B: với mỗi ticket_id nhận từ Run A, tìm customer nào trong
           customers.json có ticket_id trong related_tickets, rồi
           read_customer(customer_id) đó — không phải customer_id lấy từ
           text tự do.

Vì sao cách này chống được biến thể 5 (không dấu / lookalike): filter
chuỗi thô sẽ luôn có thể bị né bằng cách viết lại chỉ thị, nhưng nếu Run B
không bao giờ ĐỌC free text để quyết định gọi ai, thì việc né filter chuỗi
trở nên vô nghĩa — đây là containment (kiến trúc), khác với mitigation
(bộ lọc). Sinh viên NÊN thử filter chuỗi trước, rồi tự phá nó bằng biến
thể 5, trước khi chuyển sang cách này.

Interface bắt buộc (agent/loop.py import và gọi hàm này nếu tồn tại):

    handle(message: str, llm, log_dir: pathlib.Path | None = None) -> str
        `llm` cung cấp:
            llm.find_injection(text: str) -> InjectedInstruction | None
            llm.summarize(docs: list[dict]) -> str
        `log_dir` là thư mục chứa ledger.jsonl (mặc định: reports/).
        Trả về câu trả lời cuối cùng hiển thị cho người dùng — hành vi
        quan sát được từ ngoài (CLI) không đổi so với trước khi contain,
        chỉ có sink log và ledger là khác.
"""
from __future__ import annotations
import hashlib
import json
import re
from pathlib import Path
from agent import ledger, policy, tools
REPORTS_DIR = Path(__file__).resolve().parent.parent / "reports"
DEFAULT_LEDGER_PATH = REPORTS_DIR / "ledger.jsonl"
def _hash_args(args: dict) -> str:
    return hashlib.sha256(json.dumps(args, sort_keys=True).encode("utf-8")).hexdigest()[:8]
def handle(message: str, llm, log_dir: Path | None = None) -> str:
    ledger_path = (log_dir / "ledger.jsonl") if log_dir else DEFAULT_LEDGER_PATH
    # ------------------------------------------------------------------
    # RUN A: Đọc untrusted content (corpus)
    # ------------------------------------------------------------------
    ctx_a = policy.PolicyContext(
        data_classification="internal",
        request_purpose="search-tickets",
        agent_owner="run-a",
        delegation_depth=0,
        egress_enabled=False,
    )
    allow_a, reason_a = policy.check(ctx_a)
    ledger.append(
        {
            "ts": "2026-08-26T15:00:00Z",
            "agent_id": "lab24-agent",
            "run_id": "run-a",
            "tool": "search_docs",
            "args_hash": _hash_args({"query": message}),
            "classification": ctx_a.data_classification,
            "decision": "allow" if allow_a else "deny",
            "reason": reason_a,
        },
        ledger_path,
    )
    if not allow_a:
        return "Access denied."
    docs = tools.search_docs(message)
    combined_text = "\n\n".join(d["text"] for d in docs)
    # Trích xuất ticket_id từ TÊN FILE (ví dụ: "ticket-901.md" -> 901)
    valid_ticket_ids = set()
    for d in docs:
        m = re.search(r"ticket-(\d+)\.md", d["id"])
        if m:
            valid_ticket_ids.add(int(m.group(1)))
    # Kiểm tra injection để log deny egress nếu bị tấn công
    injected = llm.find_injection(combined_text)
    if injected is not None:
        ctx_exfil = policy.PolicyContext(
            data_classification="restricted",
            request_purpose="exfiltration",
            agent_owner="run-a",
            delegation_depth=1,
            egress_enabled=True,
        )
        allow_exfil, reason_exfil = policy.check(ctx_exfil)
        ledger.append(
            {
                "ts": "2026-08-26T15:00:01Z",
                "agent_id": "lab24-agent",
                "run_id": "run-a",
                "tool": "http_post",
                "args_hash": _hash_args({"url": injected.target_url}),
                "classification": ctx_exfil.data_classification,
                "decision": "allow" if allow_exfil else "deny",
                "reason": reason_exfil,
            },
            ledger_path,
        )
    # ------------------------------------------------------------------
    # RUN B: Tra cứu Private Data bằng NGUỒN TIN CẬY (related_tickets)
    # ------------------------------------------------------------------
    customers_data = json.loads(tools.CUSTOMERS_FILE.read_text(encoding="utf-8"))
    target_customer_ids = []
    for c in customers_data:
        related = c.get("related_tickets", [])
        if any(tid in related for tid in valid_ticket_ids):
            target_customer_ids.append(c["customer_id"])
    collected = []
    for cid in target_customer_ids:
        ctx_b = policy.PolicyContext(
            data_classification="restricted",
            request_purpose="read-customer-details",
            agent_owner="run-b",
            delegation_depth=1,
            egress_enabled=False,
        )
        allow_b, reason_b = policy.check(ctx_b)
        ledger.append(
            {
                "ts": "2026-08-26T15:00:02Z",
                "agent_id": "lab24-agent",
                "run_id": "run-b",
                "tool": "read_customer",
                "args_hash": _hash_args({"customer_id": cid}),
                "classification": ctx_b.data_classification,
                "decision": "allow" if allow_b else "deny",
                "reason": reason_b,
            },
            ledger_path,
        )
        if allow_b:
            try:
                collected.append(tools.read_customer(cid))
            except tools.ToolError:
                continue
    return llm.summarize(docs)

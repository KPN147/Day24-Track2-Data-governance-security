# Compliance mapping

| Requirement | Control | Evidence |
|---|---|---|
| Luật 91/2025 — quyền yêu cầu xoá | Chưa implement, xem stretch goal #3 | — |
| NĐ 356/2025 — hồ sơ xuyên biên giới 60 ngày | Data-flow inventory cho LLM API call | [reports/dpia-lite.md §3](dpia-lite.md) |
| ASI03 — privilege abuse | Per-agent identity + Policy check tại PEP | [agent/policy.py](../agent/policy.py), ledger field `agent_owner` |
| ASI01 — goal hijack | Trifecta split (Phân tách Run A / Run B) | [agent/runner.py](../agent/runner.py), [reports/attack-after.log](attack-after.log) |
| ISO 42001 Clause 5-6 | Policy-as-code có review và Hash-chain audit ledger | git log của [agent/policy.py](../agent/policy.py), [agent/ledger.py](../agent/ledger.py) |

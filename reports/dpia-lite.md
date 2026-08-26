# DPIA-lite (1 trang)

## 1. Dữ liệu gì

- **`search_docs` (Untrusted Corpus):** Đọc nội dung các ticket hỗ trợ khách hàng nằm trong thư mục [`corpus/`](../corpus), có chứa dữ liệu văn bản tự do và thông tin PII tổng hợp (synthetic).
- **`read_customer` (Private Data Store):** Đọc dữ liệu định danh khách hàng từ [`data/customers.json`](../data/customers.json), gồm các trường: `name` (Họ tên), `cccd` (Số CCCD 12 số), `phone` (Số điện thoại), `bank_account` (Số tài khoản ngân hàng), `email` và danh sách ticket liên quan `related_tickets`.

## 2. Mục đích gì

- **`search_docs`:** Giúp Agent tìm kiếm và tóm tắt thông tin các ticket theo câu hỏi hoặc yêu cầu của người dùng.
- **`read_customer`:** Phục vụ tra cứu thông tin đối soát tài khoản của khách hàng cho các ticket hợp lệ dựa trên nguồn tin cậy (`related_tickets`), không tra cứu dựa trên chỉ thị trong văn bản tự do.

## 3. Chảy đi đâu

- **Nhật ký Audit nội bộ:** Mọi thao tác gọi tool đều được kiểm soát và ghi vào nhật ký kiểm toán Append-Only chống sửa đổi tại [reports/ledger.jsonl](ledger.jsonl).
- **Exfil Sink Vector:** Dữ liệu PII bị ngăn chặn không cho xuất ra ngoài sink (`http://localhost:9999/reconcile`) nhờ Policy Enforcement Point tại [agent/policy.py](../agent/policy.py) (trả về `decision=deny`).
- **Model Provider API:** Khi sử dụng tham số `--model claude-...`, dữ liệu từ `corpus/` sẽ được truyền tới API của Anthropic (Hoa Kỳ), cấu thành việc chuyển dữ liệu xuyên biên giới theo Nghị định 356/2025. Ở chế độ mặc định `--mock`, mọi xử lý diễn ra cục bộ (local), đảm bảo không lọt dữ liệu ra ngoài.

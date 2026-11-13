# Kiến trúc AccessFlow V2

## A. Mục tiêu

Giải quyết sai sót trong vòng đời quyền truy cập: yêu cầu có căn cứ, xét duyệt theo quyền được ủy quyền, sinh luật giới hạn, kiểm chứng tác động, lưu nhật ký và thu hồi. Firewall là cơ chế thi hành có thể tích hợp, **không** phải nguồn sự thật nghiệp vụ.

## B. Thành phần

```text
[Web HTML/CSS/ES modules]
       │ HTTP JSON, signed local session cookie
       ▼
[FastAPI: REST endpoints + role authorization]
       │
       ├── [core.workflow] -- quản lý tài khoản/asset/service/entitlement/phiếu
       ├── [core.policy]   -- grant -> Rule -> first-match + trace
       ├── [core.auditor]  -- exact bounded IPv4 partitions / witness
       ├── [core.monitoring] -- CSV/Zeek -> alerts (không đồng nghĩa traffic allowed)
       ├── [core.exporters]  -- JSON / nftables DRAFT
       └── [core.reports]    -- Markdown/JSON
              │
              ▼
         [SQLite WAL]
```

## C. Mô hình nghiệp vụ

- `users`: username, hash mật khẩu, vai trò nghiệp vụ, quyền hệ thống và IP nguồn lab.
- `assets`: máy chủ, IP, độ nhạy cảm, chủ sở hữu và trạng thái.
- `services`: dịch vụ gắn asset; mỗi dịch vụ có protocol/port.
- `entitlements`: business role được phép xin truy cập service.
- `requests`: phiếu `PENDING → APPROVED/REJECTED → REVOKED/EXPIRED`.
- `traffic`: nhật ký kết nối quan sát, có dedup key.
- `audit_events`: ai tạo, đổi, phê duyệt, thu hồi, cùng thời điểm và lý do.

Luật ALLOW được sinh từ `active_access()` là `APPROVED` + chưa hết hạn + user/asset/service còn hoạt động + entitlement còn tồn tại. Sinh theo cặp `(source IP, destination IP, protocol, port)`, `default DENY`. Nếu hai phiếu giống nhau cùng phạm vi, sinh một luật nhưng giữ **cả hai provenance IDs**. Thu hồi một phiếu không làm mất quyền nếu phiếu còn lại vẫn hợp lệ.

## D. Kiểm chứng

- `trace_decision` xử lý first-match theo ưu tiên, giải thích từng điều kiện source/destination/protocol/port.
- `comparison(before,after)` chia địa chỉ nguồn/đích và cổng thành ô đồng nhất, chọn witness. Khi complete, kết luận thay đổi quyết định cho toàn phạm vi **mô hình được hỗ trợ**. Khi số ô quá lớn, `INCONCLUSIVE`.
- `audit_policy(candidate, approved)` so ALLOW-set của ứng viên với quyền đã duyệt, gắn nhãn `OVERPERMISSIVE`/`UNDERPERMISSIVE` và witness.
- Xem trước phê duyệt/thu hồi không thay database; chỉ thay khi quản lý xác nhận.

## E. API hữu ích

`POST /api/auth/login`, `GET /api/state`, `POST /api/assets`, `POST /api/services`, `POST /api/entitlements`, `POST /api/requests`, `GET /api/requests/{id}/preview?mode=approve|revoke`, `POST /api/requests/{id}/decision`, `POST /api/requests/{id}/revoke`, `POST /api/policy/simulate`, `GET /api/policy/audit`, `POST /api/policy/whatif`, `POST /api/monitor/import`, `GET /api/report/md`.

Quyền đối với thao tác ghi được kiểm tra trong cả tầng HTTP và core workflow. Employee không thể phê duyệt hay thêm tài nguyên. Một approver/admin cũng không được tự duyệt phiếu của chính mình.

## F. Mở rộng thực tế

- Adapter đọc firewall thực: kiểm tra semantic hỗ trợ, những rules có state/NAT/interface phải báo `UNSUPPORTED`; không bỏ qua im lặng.
- Thay ánh xạ IP tĩnh bằng nguồn định danh thiết bị có xác thực và lịch sử đổi IP.
- Thêm nguồn log và log firewall thực; gắn timestamp quyền ở thời điểm log.
- Đưa bước thực thi vào hàng đợi có duyệt, thử trong lab, rollback và đo kết quả trước khi cân nhắc production.

# Thiết kế và lý do từng thành phần

## 1. Câu hỏi nghiên cứu

**Một công ty phải cấp và thu hồi quyền truy cập dịch vụ mạng liên tục. Làm sao chuyển nhu cầu nghiệp vụ đã phê duyệt thành luật mạng có thể kiểm tra, thay đổi mà không mở quyền quá mức?**

Đầu vào không phải 5 luật do lập trình viên tự đặt ra. Đầu vào là **danh tính**, **vai trò nghiệp vụ**, **tài nguyên**, **dịch vụ**, **phiếu cấp quyền có thời hạn**. Các luật firewall là đầu ra suy ra từ quyền được duyệt.

## 2. Hai loại quyền không được nhầm lẫn

- **system_role (ADMIN/APPROVER/EMPLOYEE)**: ai được thực hiện hành động quản trị trong ứng dụng.
- **business_role (ACCOUNTING/HR/SALES/IT)**: chức năng nghiệp vụ, xác định tài nguyên có thể được xin phép truy cập.

Một người thuộc ACCOUNTING có entitlement đối với Accounting Application nhưng **chưa có firewall ALLOW** nếu chưa có yêu cầu được phê duyệt. Điều này buộc luồng nghiệp vụ có căn cứ, hạn chế quyền thừa.

## 3. Luồng sinh luật (quy trình thực tế)

```text
Người dùng --(gửi phiếu)--> requests:PENDING
  | yêu cầu: người gửi + đích dịch vụ + mục đích + thời hạn
  V
Approver kiểm tra: user active, service/asset active,
                    role entitlement tồn tại, không tự duyệt
  | duyệt: APPROVED (lưu decided_by, decided_at, reason)
  V
AccessService.active_access(): tính quyền hiệu lực theo thời gian
  | JOIN users + requests + services + assets + entitlements
  V
rules_from_grants(): mỗi tuple src_ip,dst_ip,protocol,port
                       => ALLOW Rule kèm provenance=[request_id]
  | nếu không có ALLOW nào khớp: default DENY
  V
Audit → Simulate → Export JSON/nftables DRAFT → Reviewer
```

**Tại sao luật tồn tại?** Quy tắc G0001 có trường `provenance` chứa id phiếu; có thể truy về người gửi, role, mục đích, thời điểm phê duyệt và hạn dùng trong database. Đây là bằng chứng nguồn gốc, không phải câu mô tả tùy ý.

## 4. Các file và hàm đáng học

| File | Hàm / lớp | Cần hiểu |
|---|---|---|
| `core/database.py` | `connect`, `transaction`, `event` | Ghi SQLite atomically, giữ audit trail |
| `core/security.py` | `hash_password`, `verify_password`, `role_check` | PBKDF2-HMAC + phân quyền hành động (lab) |
| `core/workflow.py` | `request_access`, `decide`, `active_access` | Tách quyền nghiệp vụ và quyền thực thi mạng |
| `core/workflow.py` | `change_user`, `expire_due`, `revoke_request`, `disable_asset` | Vòng đời quyền và trạng thái bất đồng bộ |
| `core/policy.py` | `Rule`, `Packet`, `rules_from_grants`, `trace_decision` | Sinh luật, ưu tiên, first-match, provenance |
| `core/auditor.py` | `partitions`, `audit_policy`, `comparison`, `analyze_rules` | Phân hoạch và kết luận kèm witness |
| `core/monitoring.py` | `parse_blob`, `import_traffic`, `analyze_traffic` | Chuẩn hóa dữ liệu quan sát, không suy đoán firewall action |
| `core/exporters.py` | `PolicyExporter`, `NftablesLabDraftExporter` | Thiết kế adapter mở; không áp dụng thật |
| `core/reports.py` | `make_report`, `markdown_report` | Xuất báo cáo từ các lớp xử lý |
| `app.py` | Các form và 6 trang | Giao diện chỉ gọi logic, không quyết định truy cập |
| `cli.py` | `main` | Có thể kiểm tra hệ thống mà không khởi động UI |

## 5. Vì sao auditor có thể kết luận chính xác trong mô hình?

Một điều kiện CIDR bao phủ một **khoảng IPv4 liên tiếp**. Điểm đầu và điểm ngay sau kết thúc của mọi CIDR là ranh giới nơi hàm match có thể đổi. Port cụ thể tạo hai biên `port`, `port+1`. Protocol thuộc TCP/UDP/ICMP. Kết hợp ranh giới của **cả chính sách ứng viên** và **quyền được phê duyệt** rồi lấy tích các khoảng. Mọi biểu thức match không đổi trong cùng một ô. Kiểm tra witness đầu ô chính là kiểm tra cả ô đó.

- `OVERPERMISSIVE`: candidate cho ALLOW nhưng không thuộc quyền hiệu lực.
- `UNDERPERMISSIVE`: quyền hiệu lực yêu cầu ALLOW nhưng candidate DENY.
- `SHADOWED`: một luật chưa bao giờ là first-match vì luật trước đã khớp.
- `REDUNDANT_ACTION`: bỏ luật mà ALLOW/DENY không đổi; chưa xét logging và các side effects.

**Giới hạn:** Số ô có thể bùng nổ theo tích các miền con. Nếu vượt `max_cells`, auditor trả `INCONCLUSIVE` và không kết luận `PASS`.

## 6. RBAC không đồng nghĩa firewall hiểu danh tính

Firewall mạng theo mô hình này xử lý IPv4/giao thức/port, không biết người đang đăng nhập. `users.source_ip` là mô hình giả định một máy/địa chỉ tĩnh cho một tài khoản. Để hoạt động thật cần thành phần trusted mapping từ IdP/NAC/DHCP/VPN hoặc thiết bị, cơ chế xác thực, bảo mật luồng điều khiển và rollback.

## 7. Nguồn log và kết luận hợp lệ

`Zeek conn.log` được chuẩn hóa thành các luồng được quan sát, không tự có nhãn ALLOW/DENY firewall. CSV có thể chứa `observed_action` từ một nguồn khác; phần mềm lưu lại nguyên trạng. `LOGGED_ALLOW_OUTSIDE_ENTITLEMENT` chỉ dựa vào trường được **khai báo trong log** chứ không tự xác thực nguồn đó. Quan sát truy cập ngoài entitlement không nhất thiết chứng tỏ firewall bị vượt qua.

Dữ liệu lịch sử được đối chiếu với tập quyền **hiện tại**; muốn kiểm toán lịch sử đúng thời điểm cần snapshot policy/grants theo thời gian và xác thực dấu thời gian.

## 8. Chiến lược nâng cấp để thành hệ thống thật

1. **Identity integration:** SSO/OIDC + RBAC/ABAC, nguồn danh tính thiết bị đáng tin; quyền thao tác kiểm toán tách với người phê duyệt.
2. **Policy adapters:** nhập cấu hình firewall thực, phân tích các match expression được hỗ trợ; báo `UNSUPPORTED`, không im lặng bỏ qua điều kiện lạ.
3. **Approval workflow:** nhiều cấp duyệt, thời hạn/khung thay đổi, phiên bản chính sách, xác nhận người chịu trách nhiệm ứng dụng.
4. **Deploy connector trong lab:** kiểm tra cú pháp nftables bằng công cụ của môi trường lab, thử canary, kiểm chứng kết nối từ điểm đo đáng tin, rollback nếu lỗi. Chưa có trong phiên bản này.
5. **Monitoring:** luồng Zeek/NetFlow + firewall decisions được chứng thực, correlation bằng connection identifiers/timestamps.
6. **Scalability:** biểu diễn tập hợp/BDD, truy vấn incremental, đo benchmark 10/20/50/100/200 rules.

Không dùng “AI” hoặc “Zero Trust” làm nhãn chung chung nếu chưa cài đặt cơ chế xác thực/ràng buộc tương ứng.

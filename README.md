# AccessFlow — Quản lý vòng đời quyền truy cập mạng và tường lửa động

**Định hướng BTCN đã chốt với giảng viên:** *Xây dựng chương trình mô phỏng tường lửa và kiểm soát truy cập mạng.* Phần mềm hiện thực đề tài ở mức **quản lý truy cập dựa trên nghiệp vụ**: luật firewall không phải 5 dòng JSON cố định, mà được **sinh từ quyền được phê duyệt**, kiểm toán, giám sát và thu hồi khi hết hạn.

**Công nghệ:** Python 3.10+, SQLite (`sqlite3` có sẵn), Streamlit (giao diện web), unittest (kiểm thử); chạy cục bộ trên Windows, macOS hoặc Linux. Không cần tài khoản đám mây.

> **Phạm vi bảo mật:** Đây là *prototype lab*, không phải dịch vụ quản lý danh tính đã harden cho production. Ứng dụng không bắt gói tin, không thực thi/triển khai nftables, không chứng thực quyền sở hữu địa chỉ IP của thiết bị, không tích hợp DHCP/IdP/VPN. Không public Streamlit ra Internet. Các tài khoản demo và mật khẩu mặc định chỉ để học tập.

## I. Chạy từng bước trên Windows bằng VS Code

**1.** Giải nén ZIP. Vào thư mục `Firewall_Access_Lifecycle`, nơi thấy `app.py`, `cli.py`, `requirements.txt`, thư mục `core/` và `tests/`.

**2.** VS Code → **File → Open Folder** → chọn đúng thư mục đó. Chọn **Terminal → New Terminal**. Kiểm tra Python:

```powershell
python --version
```

Nếu máy chỉ nhận `py`, hãy thay `python` bằng `py` trong các lệnh tiếp theo.

**3.** Cài Streamlit:

```powershell
python -m pip install -r requirements.txt
```

**4.** Chạy ứng dụng:

```powershell
python -m streamlit run app.py
```

Lần đầu Streamlit có thể hỏi email → để trống rồi bấm Enter. Mở **http://localhost:8501** trong Chrome/Edge. Nếu V2/V3 cũ còn chiếm cổng, nhấn `Ctrl+C` ở Terminal cũ hoặc chạy:

```powershell
python -m streamlit run app.py --server.port 8502
```

**5.** Ở lần chạy đầu, chương trình tự khởi tạo `runtime/access.sqlite3` và tài khoản lab. Đăng nhập:

| Tài khoản | Vai trò hệ thống | Vai trò nghiệp vụ | Mật khẩu **lab** |
|---|---|---|---|
| `admin` | ADMIN | IT | `Demo@2026!` |
| `approver` | APPROVER | IT | `Demo@2026!` |
| `linh` | EMPLOYEE | ACCOUNTING | `Demo@2026!` |
| `mai` | EMPLOYEE | HR | `Demo@2026!` |
| `nam` | EMPLOYEE | SALES | `Demo@2026!` |
| `quang` | EMPLOYEE | ACCOUNTING | `Demo@2026!` |

**Đổi mật khẩu trong mục 6** nếu muốn lưu dữ liệu lâu dài. Các tài khoản trên dùng thông tin giả định. Đừng đưa mật khẩu này lên một ứng dụng có thể truy cập từ Internet.

**6.** Nhấn `Ctrl+C` ở Terminal chạy Streamlit để tắt. Dữ liệu được lưu trong SQLite: tắt/mở ứng dụng **không làm mất thay đổi**.

## II. Sáu chức năng thực sự hoạt động

| Phân hệ | Tệp xử lý chính | Ý nghĩa thực tế |
|---|---|---|
| 1. Quản lý tài nguyên mạng | `core/workflow.py`, `core/database.py` | Thêm người dùng, IP thiết bị, máy chủ, dịch vụ, độ nhạy cảm, chủ sở hữu |
| 2. RBAC / quyền chuẩn | `core/workflow.py`, bảng `entitlements` | Vai trò có quyền **đề nghị** dịch vụ nào (không tự động mở firewall) |
| 3. Yêu cầu và phê duyệt | `core/workflow.py` | Phiếu có mục đích/thời hạn, phê duyệt/từ chối, ngăn tự duyệt, kiểm tra entitlement |
| 4. Sinh và kiểm toán luật | `core/policy.py`, `core/auditor.py`, `core/exporters.py` | Từ quyền APPROVED sinh ALLOW cụ thể, mô phỏng first-match, tìm quyền thừa/thiếu qua witness, xuất bản nháp |
| 5. Giám sát và rủi ro | `core/monitoring.py` | Nhập CSV/Zeek JSONL, đối chiếu luồng với quyền, phân loại cảnh báo, đánh giá rủi ro dạng quy tắc |
| 6. Vòng đời và báo cáo | `core/workflow.py`, `core/reports.py` | Hết hạn, thu hồi, chuyển vai trò, đổi IP, nghỉ việc, vô hiệu hóa tài nguyên, audit trail, tải báo cáo |

**Điểm cốt lõi:** yêu cầu kết nối mạng (packet) **không tự sinh ALLOW**. Một **phiếu yêu cầu cấp quyền** được phê duyệt mới có thể sinh luật, dựa trên vai trò và tài nguyên đã khai báo.

## III. Demo end-to-end cho thầy — không lệ thuộc 5 luật mẫu

**Tình huống 1 — Mở quyền cho một nhân viên theo nghiệp vụ**

1. Đăng nhập `quang` (EMPLOYEE) → **3. Yêu cầu & phê duyệt** → chọn `Accounting Application / HTTPS` → nêu mục đích, đặt 2 ngày → gửi. Trạng thái `PENDING`.
2. Đăng xuất → vào `approver` → **3. Yêu cầu & phê duyệt** → chọn phiếu của Quang → APPROVE, điền lý do. Nếu không có quyền chuẩn cho ACCOUNTING, hệ thống từ chối phê duyệt.
3. Vào **4. Sinh luật & kiểm toán** → xuất hiện luật ALLOW nguồn `10.10.10.11` → đích `10.20.1.10` TCP/443, có `provenance` chứa mã phiếu.
4. Nhập packet trên để thấy ALLOW. Nhập `10.10.30.10` (SALES) đến cùng đích để thấy DENY.
5. Vào **6. Vòng đời** → thu hồi phiếu vừa duyệt. Quay lại **4** → luật đó không còn được sinh. Đây là cơ chế thu hồi quyền có hiệu lực ngay trong mô phỏng.

**Tình huống 2 — Phát hiện ALLOW quá rộng**

1. Đăng nhập `admin` → **4. Sinh luật & kiểm toán**.
2. Ở What-if, tải `samples/what_if_broad.json`.
3. Hệ thống báo `OVERPERMISSIVE` (cho quá nhiều nguồn truy cập ứng dụng kế toán) và `UNDERPERMISSIVE` (bỏ qua các quyền hợp lệ khác), kèm witness và số vùng quyết định thay đổi.
4. File này **chỉ được so sánh**, không ghi đè quyền được phê duyệt hay luật có hiệu lực.

**Tình huống 3 — Giám sát từ dữ liệu quan sát**

1. Vào **5. Giám sát truy cập** bằng `admin`/`approver`.
2. Tải `samples/traffic.csv`, chọn `csv`, bấm **Nhập log**. Có thể thử `samples/zeek_conn.jsonl` với định dạng `zeek`.
3. Hệ thống phân loại các luồng không thuộc quyền đã được phê duyệt. Với log CSV chứa `observed_action=ALLOW`, kết quả là `LOGGED_ALLOW_OUTSIDE_ENTITLEMENT` — chỉ đáng tin nếu cột ALLOW đến từ nhật ký thực thi đáng tin cậy.
4. Mục **6** cho phép tải báo cáo kiểm toán Markdown hoặc JSON.

**Tình huống 4 — Logic mở**

1. Admin tạo máy chủ `New CRM` IP `10.20.4.10` và dịch vụ HTTPS TCP/443 ở **1**.
2. Admin cấp entitlement `SALES → New CRM/HTTPS` ở **2**.
3. `nam` gửi phiếu ở **3**; `approver` phê duyệt; ở **4** xuất hiện luật mới đúng IP/port và nguồn gốc phiếu mà **không sửa dòng code nào**.

## IV. Chạy qua Terminal — không cần Streamlit

Khởi tạo database lab (chỉ thực hiện seed nếu database trống):

```powershell
python cli.py init
python cli.py status
python cli.py policy
python cli.py simulate --src 10.10.10.10 --dst 10.20.1.10 --proto TCP --port 443
python cli.py audit
python cli.py analyze
python cli.py compare samples/what_if_broad.json
python cli.py export generated_policy.json
python cli.py export-nft-lab-draft firewall_lab_draft.nft
python cli.py report
```

Nhập log bằng CLI (chỉ sử dụng tài khoản demo trong lab):

```powershell
python cli.py import-traffic samples/traffic.csv --format csv --actor admin --password "Demo@2026!"
python cli.py monitor
python cli.py expire --actor admin --password "Demo@2026!"
```

Lưu ý: truyền mật khẩu qua tham số CLI có thể bị ghi vào lịch sử lệnh; **chỉ dùng cách này trong lab với mật khẩu demo**. Khi triển khai thực tế cần dùng prompt bảo mật, xác thực phù hợp và không đưa mật khẩu lên dòng lệnh.

## V. Kiểm thử

```powershell
python -m unittest discover -s tests -v
```

Mã nguồn đã được kiểm thử bằng Python 3.13 (49 test thành công khi đóng gói). Chạy lại trên máy của bạn để lưu ảnh Terminal cho báo cáo. Thư viện Streamlit chưa được khởi chạy bằng trình duyệt trong môi trường tạo ZIP, vì vậy cần xác nhận UI trên máy cá nhân.

## VI. Logic mở và khả năng tích hợp trong thực tế

- **Dữ liệu mở:** tạo người dùng, tài nguyên, dịch vụ, vai trò, phiếu mới trong SQLite; không hard-code 5 luật R1–R5.
- **Chính sách mở:** `Rule` là dữ liệu chuẩn hóa; `core/exporters.py` có giao diện `PolicyExporter`, `JSONExporter` và `NftablesLabDraftExporter`. Có thể bổ sung adapter cho firewall khác mà giữ nguyên nghiệp vụ.
- **Giám sát mở:** `parse_blob()` nhận CSV hoặc Zeek conn.log dạng JSON-lines, có thể bổ sung adapter khác.
- **Tách lớp:** Streamlit gọi `AccessService`/Policy/Auditor; lớp xử lý hoạt động độc lập qua CLI và unit test.
- **Kiểm chứng:** audit so sánh tập lưu lượng ALLOW của chính sách ứng viên với quyền đã duyệt. Phân hoạch chính xác mọi ranh giới CIDR/port; `INCONCLUSIVE` khi vượt `max_cells`, không nói là PASS khi chưa chứng minh.
- **Lộ trình thực:** kết nối IdP/DHCP để xác thực người–thiết bị–IP; nhập cấu hình firewall thực (với unsupported semantics được báo lỗi); duyệt thay đổi, kiểm chứng trên VM cách ly, rollback, rồi mới cân nhắc triển khai có kiểm soát.

## VII. Giới hạn trung thực

1. **Không phải firewall vận hành thật.** Hệ thống hỗ trợ quản lý cấp quyền và mô phỏng ALLOW/DENY. Tệp nftables chỉ là **bản nháp lab**, không được kiểm tra cú pháp bằng nft trên môi trường hiện tại và không tự áp dụng.
2. **Không phải IAM/RBAC production.** Login Streamlit, không có SSO/MFA, rate limiting, HTTPS reverse proxy, bảo vệ chống chỉnh DB trực tiếp hoặc hardening triển khai. SQLite local phù hợp học tập và prototype đơn máy.
3. **IP không phải danh tính.** Chỉ minh họa mỗi người có IPv4 tĩnh duy nhất; không giải quyết NAT, DHCP, mạng không tin cậy, shared device và mạo danh IP.
4. **Giám sát không chứng minh firewall đã ALLOW.** Zeek quan sát kết nối, có thể thấy cả lưu lượng bị chặn ở điểm khác; lịch sử log hiện **được so sánh với quyền hiện hành**, chưa tái dựng quyền tại thời điểm log. Risk score chỉ là heuristic.
5. **Audit hữu hạn:** IPv4 stateless, TCP/UDP/ICMP, destination port; không có state, NAT, IPv6, source port, TCP flags, interface. Nếu số ô phân hoạch quá lớn trả INCONCLUSIVE.
6. **Chính sách được sinh từ quyền duyệt, không tự suy ra quyền từ traffic.** Entitlement là cấu hình nghiệp vụ do người có thẩm quyền định nghĩa; đây là lý do mỗi ALLOW có căn cứ.
7. **Expiration:** hết hạn được loại khỏi luật *ngay khi đọc* dù chưa bấm đồng bộ. Muốn chuyển trạng thái trong database phải chạy Đồng bộ hoặc `cli.py expire` (có thể nối scheduler tương lai).
8. **Đầu ra nftables chỉ cho mô hình forward IPv4 lab.** Không bao gồm NAT/state/interface hoặc cấu hình đang tồn tại. Không chạy trên máy kết nối thật chỉ vì đã sinh được file.

## VIII. Cấu trúc thư mục

```text
Firewall_Access_Lifecycle/
├── app.py                # Streamlit — 6 phân hệ
├── cli.py                # CLI độc lập
├── requirements.txt      # streamlit
├── core/
│   ├── database.py       # SQLite, transaction, audit trail
│   ├── security.py       # hash mật khẩu, kiểm tra quyền hệ thống
│   ├── workflow.py       # tài nguyên, entitlement, cấp/duyệt/thu hồi
│   ├── demo.py           # dữ liệu doanh nghiệp giả định
│   ├── policy.py         # Rule, Packet, generator, first-match
│   ├── auditor.py        # exact partition, witness, what-if, shadowing
│   ├── monitoring.py     # CSV/Zeek logs, rủi ro
│   ├── exporters.py      # JSON/nftables lab DRAFT adapters
│   └── reports.py        # xuất báo cáo
├── samples/
│   ├── traffic.csv
│   ├── zeek_conn.jsonl
│   └── what_if_broad.json
├── docs/
│   ├── THIET_KE_VA_LUONG_XU_LY.md
│   └── KICH_BAN_BAO_VE.md
├── tests/
│   └── test_system.py
└── runtime/              # tự tạo khi chạy; KHÔNG đưa vào ZIP
```

**Đọc tiếp:** `docs/THIET_KE_VA_LUONG_XU_LY.md` để hiểu từng module, `docs/KICH_BAN_BAO_VE.md` để chuẩn bị trả lời thầy.

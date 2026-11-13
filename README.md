# AccessFlow V2 — Network Access Lifecycle & Firewall Policy Platform

**Đề tài BTCN đã đăng ký:** *Xây dựng chương trình mô phỏng tường lửa và kiểm soát truy cập mạng.*

**Vấn đề thực tế:** Tại doanh nghiệp, quyền truy cập tài nguyên thường được cấp qua nhiều bước thủ công. Nếu không truy vết nguồn gốc, duyệt theo vai trò, xác minh thay đổi và thu hồi theo vòng đời, chính sách tường lửa dễ trở nên khó quản lý hoặc cấp quá nhiều quyền. AccessFlow V2 mô hình hóa toàn bộ quy trình **yêu cầu nghiệp vụ → RBAC → phê duyệt → chính sách tường lửa → kiểm chứng → giám sát → thu hồi**.

**Lưu ý trung thực:** Đây là **prototype cục bộ**, không phải thiết bị tường lửa thật, không chặn packet, không tự áp dụng nftables và **không phải IAM production**. Đừng công khai ứng dụng ra Internet hoặc dùng các tài khoản demo trong môi trường thực tế.

![Giao diện tổng quan AccessFlow V2](docs/dashboard_preview.png)

## 1. Cài đặt và chạy trên Windows bằng VS Code

**Yêu cầu:** Python 3.10 trở lên (Python 3.13 của bạn dùng được). Không cần Node.js, npm hay Streamlit. Kết nối Internet chỉ để cài thư viện Python lần đầu.

1. Giải nén ZIP rồi vào thư mục `AccessFlow_V2` (nơi có `run.py`, `requirements.txt`, `backend/`, `web/` và `core/`).
2. Trong VS Code: **File → Open Folder** chọn `AccessFlow_V2` → **Terminal → New Terminal**.
3. Chạy lần lượt:

```powershell
python -m pip install -r requirements.txt
python run.py
```

4. Trình duyệt mở **http://127.0.0.1:8000**. Nếu máy báo `python` không tồn tại, thay bằng `py`.
5. Để dừng: nhấn `Ctrl+C` ở Terminal. Các dữ liệu thêm/sửa vẫn được lưu trong `runtime/access.sqlite3`.

Có thể nhấn đúp `install_windows.bat` rồi `run_windows.bat` để cài/chạy. Nếu port 8000 bị chiếm, dùng `python run.py --port 8001` rồi vào `http://127.0.0.1:8001`.

**Tài khoản lab** (tất cả có mật khẩu mặc định **`Demo@2026!`**):

| Username | System role | Business role | Công việc thử nghiệm |
|---|---|---|---|
| `admin` | `ADMIN` | `IT` | Tạo người dùng, tài nguyên, role entitlement |
| `approver` | `APPROVER` | `IT` | Xét duyệt/thu hồi, kiểm toán và nhập log |
| `nam` | `EMPLOYEE` | `SALES` | Gửi phiếu truy cập CRM |
| `linh` | `EMPLOYEE` | `ACCOUNTING` | Yêu cầu ứng dụng kế toán |
| `mai` | `EMPLOYEE` | `HR` | Yêu cầu ứng dụng nhân sự |
| `quang` | `EMPLOYEE` | `ACCOUNTING` | Phiếu mẫu chờ duyệt |

Đổi mật khẩu tại **Vòng đời & nhật ký → Đổi mật khẩu** nếu muốn giữ dữ liệu lab lâu dài. Chỉ dùng trên localhost.

## 2. Sáu nhóm chức năng (và trang tổng quan)

| Phân hệ | Hành động thực sự được thực hiện |
|---|---|
| **1. Tài nguyên & danh tính** | Tạo và xem **riêng** các máy chủ, dịch vụ và tài khoản; máy chủ chưa có dịch vụ vẫn hiện. Báo trùng IP bằng tiếng Việt, không văng lỗi SQLite. |
| **2. Vai trò & quyền chuẩn** | Khai báo `ROLE → SERVICE`, thu hồi entitlement và các quyền APPROVED liên quan. Entitlement chỉ là **được phép xin**, không tự sinh ALLOW. |
| **3. Yêu cầu & phê duyệt** | Nhân viên nêu mục đích/thời hạn; quản lý xem trước sự thay đổi của tập luật và **witness** trước khi duyệt/từ chối; ngăn tự duyệt. |
| **4. Firewall & kiểm chứng** | Sinh ALLOW theo từng quyền còn hiệu lực, `default DENY`; mô phỏng first-match kèm dấu vết; kiểm toán what-if JSON, so sánh before/after; xuất JSON và nftables lab **draft**. |
| **5. Giám sát & rủi ro** | Nhập CSV hoặc Zeek JSONL, bỏ log trùng, thống kê các kết nối ngoài quyền và phân loại rủi ro theo heuristic. |
| **6. Vòng đời & nhật ký** | Thu hồi có xem trước ảnh hưởng, đồng bộ hết hạn, chuyển vai trò/đổi IP, vô hiệu hóa máy chủ, audit trail và xuất báo cáo Markdown/JSON. |

**Trang tổng quan:** KPI theo dữ liệu, các gợi ý ưu tiên rà soát, bản đồ kết nối của những quyền đã duyệt, lịch sử hành động và sơ đồ vòng đời.

## 3. Kịch bản bảo vệ thực tế: CRM cho phòng Kinh doanh

Bộ dữ liệu có sẵn cho Kế toán, Nhân sự, Portal, DNS, DB. Người dùng thử **tạo CRM hoàn toàn mới** để chứng minh tính mở:

1. Đăng nhập **`admin` → Tài nguyên mạng → Thêm máy chủ**: nhập `CRM Lab`, IP `10.20.4.10`, phòng ban `SALES`, mức `MEDIUM`, chủ sở hữu `Phòng Kinh doanh` → lưu. **CRM xuất hiện ngay cả khi chưa có dịch vụ**.
2. **Thêm dịch vụ**: chọn CRM Lab, `HTTPS`, `TCP`, port `443` → lưu. Nếu tạo trùng IP hoặc trùng service, hệ thống trả thông báo dễ hiểu.
3. **Vai trò & quyền chuẩn → Thêm quyền chuẩn**: chọn vai trò `SALES`, dịch vụ `CRM Lab / HTTPS`.
4. **Đăng xuất → đăng nhập `nam` → Yêu cầu truy cập**: chọn CRM Lab, nêu mục đích, thời hạn 3 ngày → gửi. Phiếu `PENDING`, firewall **chưa sinh luật**.
5. **Đăng xuất → đăng nhập `approver` → Yêu cầu truy cập**: mở phiếu CRM của Nam → **xem trước tác động**, witness và số ô phân hoạch thay đổi → duyệt, nêu lý do.
6. **Firewall & kiểm chứng**: xuất hiện ALLOW `10.10.30.10 → 10.20.4.10 / TCP 443`, kèm mã phiếu. Thử mô phỏng IP nguồn khác → DENY.
7. **Vòng đời & nhật ký → Xem & thu hồi** phiếu → xem tác động và xác nhận. Quay lại **Firewall & kiểm chứng**, kết nối trên đổi thành DENY trong mô phỏng.
8. **Giám sát & rủi ro**: nhập file `samples/traffic.csv` ở định dạng CSV, thử `samples/zeek_conn.jsonl` ở định dạng Zeek.

Ảnh tham khảo trong thư mục `docs/`.

## 4. Kiến trúc mã nguồn

```text
AccessFlow_V2/
├── run.py                      # Lệnh chạy duy nhất: FastAPI + giao diện web
├── backend/
│   ├── app.py                 # REST API, schema, kiểm quyền theo vai trò
│   ├── auth.py                # Cookie ký HMAC, giới hạn thử sai cơ bản
│   └── insights.py            # Gợi ý rủi ro từ dữ liệu đang có
├── web/
│   ├── index.html
│   ├── styles.css             # Thiết kế responsive, tự viết, không dùng CDN
│   └── js/
│       ├── app.js             # Điều phối UI / sự kiện
│       ├── api.js             # Giao tiếp API
│       ├── views.js           # 7 trang giao diện
│       └── utils.js           # SVG icons, bảng, format, escape HTML
├── core/
│   ├── database.py            # SQLite WAL, transactions, audit trail
│   ├── security.py            # Hash password, IP validation, role gates
│   ├── workflow.py            # Entitlement, request, approve, revoke, expiry
│   ├── policy.py              # Rule generator, first-match, provenance
│   ├── auditor.py             # Exact partition, witness, shadowing, what-if
│   ├── monitoring.py          # Đọc CSV/Zeek log, đánh giá dấu hiệu
│   ├── exporters.py           # Xuất JSON/nftables bản nháp phòng lab
│   ├── reports.py             # Báo cáo kiểm toán
│   └── demo.py                # Seed tài khoản/tài nguyên giả định
├── tests/
│   ├── test_system.py         # 49 kiểm thử nghiệp vụ cũ
│   └── test_api.py            # 6 kiểm thử REST API tích hợp
├── samples/                   # Bộ dữ liệu log và chính sách sai
├── docs/                      # Kiến trúc, kiểm thử, hướng bảo vệ
└── runtime/                   # TỰ TẠO / .gitignore / không đóng trong ZIP
```

**Điểm mạnh thiết kế:** Core không phụ thuộc giao diện. FastAPI làm HTTP API; phần web là HTML/CSS/JavaScript chia module không dùng thư viện ngoài nên **một lệnh Python chạy được hết**. Có thể thay web bằng React/Vue, thay exporter cho firewall khác, thêm adapter nhập log mà không cần viết lại phần lõi.

## 5. Test và chạy CLI

```powershell
python -m unittest discover -s tests -v
python cli.py status
python cli.py audit
python cli.py compare samples/what_if_broad.json
```

**Kiểm thử trên máy đóng gói:** 49 test core + 6 test tích hợp REST = **55/55 đạt** (xem `docs/KIEM_THU_V2.md`). Màn hình login, dashboard, inventory và luồng CRM đã được dựng/chạy bằng Chromium kết hợp API từ FastAPI TestClient. Việc truy cập trực tiếp bằng Chrome/Edge trên máy Windows cần được xác nhận khi bạn chạy local.

Có thể xem API mô tả tại **http://127.0.0.1:8000/api/docs** (Swagger UI phụ thuộc tài nguyên ngoài nếu mạng chặn; không cần Swagger để dùng web).

## 6. Chuyển từ phiên bản đã đẩy lên GitHub

**Không ghi đè ngay vào bản V1 đang chạy khi chưa test.** Hãy thử V2 ở thư mục riêng trước. Khi đã đồng ý:

1. Trong repo Git trên Windows: `git switch -c feature/accessflow-v2` để tạo nhánh mới.
2. Sao lưu `runtime/access.sqlite3` nếu đang dùng dữ liệu thực hành. Không commit `runtime/`.
3. Copy **nội dung bên trong** thư mục `AccessFlow_V2/` vào thư mục repo, thay các file cũ cùng tên. Xóa `app.py` và các lệnh chạy Streamlit cũ để tránh nhầm lẫn.
4. Chạy `python -m pip install -r requirements.txt`, `python -m unittest discover -s tests -v`, rồi `python run.py`.
5. Chỉ khi kiểm thử đạt và UI hoạt động thì `git add .`, `git commit -m "Redesign AccessFlow V2 web platform"`, `git push -u origin feature/accessflow-v2`.

Core vẫn sử dụng schema SQLite cũ, giữ nguyên dữ liệu nếu copy database vào `runtime/access.sqlite3` trong thư mục V2; **đảm bảo sao lưu trước khi đổi phiên bản**.

## 7. Giới hạn / điều chưa thể khẳng định

- **Chưa chặn gói tin thật**, chưa tương tác trực tiếp nftables hoặc Windows Firewall, chưa tự đẩy cấu hình, chưa rollback mạng thật. Bản nháp nftables không phải file production.
- `default DENY` và first-match chỉ cho IPv4 stateless TCP/UDP/ICMP, destination port. Không hỗ trợ state tracking, NAT, IPv6, source port, interface, routing.
- RBAC dựa trên dữ liệu vai trò được cấu hình, không định danh danh tính mạng đáng tin cậy. IP tĩnh lab không chứng minh chủ sở hữu máy; thực tế cần IdP/DHCP/VPN/agent.
- Phân hoạch logic chỉ **chính xác trong mô hình hỗ trợ nếu complete=true**. Quá `max_cells` thì `INCONCLUSIVE`, không được hiểu là PASS.
- Baseline audit dùng quyền đã duyệt làm nguồn chuẩn; nó kiểm tra **tính nhất quán nội bộ**, không chứng nhận mạng an toàn. What-if với chính sách độc lập phát hiện cấp quyền quá rộng/thiếu quyền.
- Điểm rủi ro chỉ là heuristic. Zeek không có hành động ALLOW/DENY của firewall; log được so sánh với **quyền hiện tại**, chưa tái dựng lịch sử quyền ở thời điểm phát sinh log.
- Cơ chế phiên ký cookie chỉ hỗ trợ **prototype localhost**, không có SSO/MFA, CSRF hardening hoàn chỉnh, rate limit bền vững hay audit log chống sửa DB. Không public dịch vụ trên Internet.

**Khi trình bày thầy:** Các luật ALLOW là *kết quả* của phê duyệt dựa trên yêu cầu nghiệp vụ và entitlement, không phải 5 luật đặt tùy ý. Quan trọng nhất là chứng minh được việc cấp/thay đổi/thu hồi quyền và tác động chính sách với input mới bất kỳ trong mô hình hỗ trợ.

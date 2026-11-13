# Kiểm thử AccessFlow V2

## 1. Cách chạy

```powershell
python -m unittest discover -s tests -v
```

**Kết quả lúc đóng gói:** 55/55 tests thành công gồm 49 tests core/workflow + 6 tests REST API mới.

## 2. Những trường hợp mới

1. Đăng nhập sai trả 401, đăng nhập đúng tạo phiên, đăng xuất hủy phiên, metrics lấy dữ liệu SQLite thực.
2. Tạo máy chủ CRM: `assets` tăng, xuất hiện ngay khi chưa có service; IP trùng trả HTTP 409 và thông báo thân thiện; tạo HTTPS/TCP/443 hiển thị trong bảng service.
3. Employee bị chặn khi tạo asset hoặc truy cập API kiểm toán quản trị.
4. Phiếu chờ duyệt của Quang: xem trước tác động; duyệt tăng ALLOW; mô phỏng nguồn đúng nhận ALLOW; xem trước thu hồi; thu hồi xong trả DENY.
5. Chính sách ứng viên có ALLOW quá rộng: audit trả `VIOLATIONS` và `OVERPERMISSIVE`. Nhập log mẫu, tải báo cáo và nháp nftables.
6. Kịch bản CRM end-to-end: admin tạo asset/service/entitlement SALES, Nam gửi yêu cầu, approver phê duyệt, firewall mô phỏng đúng nguồn đích cổng trả ALLOW.

## 3. Kiểm thử giao diện

Đã render giao diện Chromium (dùng FastAPI TestClient làm lớp chuyển tiếp trong môi trường bị hạn chế browser networking) và chạy các tương tác:

- Đăng nhập và dashboard, đọc dữ liệu 6 users, 5 assets, 5 services.
- Tạo CRM -> bảng tài nguyên tăng lên 6 -> thêm HTTPS -> bảng services tăng lên 6.
- Thêm entitlement SALES -> CRM -> Nam gửi phiếu -> approver duyệt sau preview -> truy vấn firewall cho Nam/CRM/TCP/443 trả ALLOW.
- Không phát sinh JavaScript `pageerror` trong luồng thử đó.

Ảnh UI: `login_preview.png`, `dashboard_preview.png`, `assets_preview.png`, `assets_crm_preview.png`, `policy_preview.png`.

**Giới hạn kiểm thử:** Môi trường tạo gói không cho Chromium trực tiếp đi tới HTTP loopback nên bước kiểm thử visual dùng API TestClient làm transport, **không** tương đương xác nhận Chrome/Edge trên Windows. Cần thử trên máy Windows của bạn theo README. Không thử áp dụng nftables lên firewall thật.

## 4. Phân loại kết quả

- Chạy test tự động 55/55: đạt tại lúc đóng gói.
- UI qua Chromium + API TestClient: đạt kịch bản được kiểm tra.
- Truy cập HTTP qua trình duyệt Windows: chưa được xác nhận tại lúc đóng gói.
- Kiểm thử hiệu năng với 100+ firewall rules: chưa thực hiện, không nên tuyên bố đã đạt.
- Firewall production: ngoài phạm vi bản V2.

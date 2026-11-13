# Kịch bản demo khoảng 7 phút và câu hỏi bảo vệ

## Mạch trình bày

**0:00–0:45** — Tên đề tài vẫn là *mô phỏng tường lửa và kiểm soát truy cập mạng*. Bài toán chính: quyền truy cập của nhân viên thay đổi theo vai trò, mục đích và thời gian; viết luật tường lửa thủ công dẫn đến khó truy vết và thu hồi.

**0:45–1:30** — Mở phân hệ 1, 2: giải thích người dùng ACCOUNTING, HR, SALES, máy chủ và service. Khác biệt giữa quyền chuẩn theo vai trò và quyền mạng đã được phê duyệt.

**1:30–3:20** — Đăng nhập `quang`, gửi phiếu tới Accounting Application; đăng nhập `approver`, phê duyệt. Mở phân hệ 4: luật Gxxxx xuất hiện kèm nguồn `10.10.10.11`, đích `10.20.1.10`, TCP/443 và `provenance` chứa mã phiếu. Mô phỏng nguồn ngoài SALES vẫn DENY.

**3:20–4:30** — Upload `samples/what_if_broad.json` ở phân hệ 4. Hệ thống phát hiện quyền mở rộng `ANY` tạo `OVERPERMISSIVE` và bỏ mất quyền của dịch vụ khác tạo `UNDERPERMISSIVE`, đưa witness.

**4:30–5:30** — Nhập `samples/traffic.csv` ở phân hệ 5: cho thấy log đối chiếu với quyền đã cấp; phân biệt `observed_action` và quyết định do chương trình mô phỏng.

**5:30–6:30** — Phân hệ 6: thu hồi quyền của Quang, luật liên quan biến mất ngay; xuất báo cáo Markdown. Giới thiệu file cấu hình nftables DRAFT chỉ dành cho lab.

**6:30–7:00** — Nêu giới hạn: IP không tự xác thực người, không firewall live; tính mở đến từ module, dữ liệu thay đổi được, exporter/adapter và kiểm chứng quyền.

## Câu hỏi & trả lời

**Q1. Vì sao chọn một luật ALLOW cho nhân viên?** Vì có một phiếu APPROVED gắn với người, role, dịch vụ và thời hạn; `Rule.provenance` truy ngược được phiếu. Không tự gõ luật theo ý thích.

**Q2. Tại sao phòng Kế toán được cấp nhưng Kinh doanh không?** Quyền chuẩn do nhà quản trị định nghĩa: ACCOUNTING có entitlement tới Accounting Application, SALES không có. Dữ liệu quyền chuẩn là chính sách nghiệp vụ phải có chủ sở hữu phê duyệt.

**Q3. Người dùng tự gửi yêu cầu có tạo ALLOW không?** Không. PENDING chưa có hiệu lực. Approver không được tự phê duyệt và service cũng kiểm tra RBAC.

**Q4. Người bị thu hồi còn kết nối được không?** Trong mô phỏng stateless, luật ALLOW của quyền đó biến mất. Trong mạng thật, cần kết nối với enforcement point và xử lý trạng thái kết nối đang mở; dự án chưa triển khai.

**Q5. Tại sao auditor được gọi là chính xác?** Các predicate là các khoảng địa chỉ/port tĩnh; phân hoạch tại mọi biên, nên match không đổi trong từng ô. Kết luận chỉ đúng trong mô hình và khi duyệt hết ô. Giới hạn vượt thì INCONCLUSIVE.

**Q6. Lưu lượng được quan sát có chứng minh firewall ALLOW không?** Không. Nó có thể được quan sát trước điểm lọc hoặc là một lần thử kết nối. Muốn chứng minh firewall cho qua phải có log quyết định/điểm đo đáng tin.

**Q7. Đề tài có sẵn kết nối đến firewall thật chưa?** Chưa. Nó xuất JSON và bản nháp nftables cho gateway lab; không tự chạy lệnh/cấu hình firewall. Hướng triển khai thật cần adapter nhập policy, validation, approval, kiểm chứng, rollback và xác thực thiết bị.

**Q8. Có phải RBAC production không?** Không; chỉ là prototype cục bộ. Hệ thống chưa có SSO, MFA, bảo vệ ứng dụng production, định danh thiết bị tin cậy, audit log bất biến.

**Q9. 200 luật thì sao?** Không bảo đảm tuyến tính. `audit_policy` có ngưỡng số ô; nếu vượt, kết quả INCONCLUSIVE. Hướng cải tiến: incremental analysis, BDD hoặc giải thuật phân hoạch hiệu quả hơn và benchmark thực tế.

**Q10. Vì sao có thể thay đổi bộ luật mà không sửa code?** Vì quy tắc ALLOW được sinh từ dữ liệu của người, quyền, service và approvals. Mở thêm vai trò/tài nguyên/yêu cầu mới tạo điều kiện sinh luật mới mà không hard-code.

# Giải thích và chuẩn bị trả lời câu hỏi bảo vệ

**Q: Đề tài giải quyết vấn đề gì?**

A: Giải quyết vòng đời quản lý quyền mạng của tổ chức. Khi quyền được xin, duyệt, thay đổi hoặc thu hồi, chính sách cần thay đổi nhất quán, có bằng chứng và truy vết được. Tường lửa đóng vai trò chính sách thực thi được mô phỏng; sinh luật là kết quả của nghiệp vụ.

**Q: Vì sao chọn luật này?**

A: Không chọn tùy ý. Một ALLOW tương ứng một hoặc nhiều phiếu được duyệt, một cặp IP nguồn–đích, protocol và port của dịch vụ. Trong code `Rule.provenance` giữ mã phiếu. Khi phiếu không hợp lệ nữa, luật bị loại khỏi bộ luật được sinh.

**Q: RBAC đóng vai trò gì?**

A: Role entitlement chỉ cho phép một người có vai trò nghiệp vụ nhất định *xin quyền* tới dịch vụ. Quyền chỉ có hiệu lực sau khi một quản lý khác phê duyệt; do đó RBAC không tự sinh ALLOW cho mọi người trong role.

**Q: Hệ thống có bảo vệ mạng thật không?**

A: Không. V2 là hệ thống quản lý truy cập và mô phỏng kiểm soát truy cập; hỗ trợ xuất JSON và nháp nftables. Kết nối với firewall thật đòi hỏi adapter biết đủ semantic, thẩm định chính sách, thử nghiệm cách ly, phê duyệt và rollback.

**Q: Tại sao có `exact partition`?**

A: Vì với các mạng IPv4 và cổng đã xuất hiện trong rules, trạng thái khớp luật là bất biến trong mỗi ô phân hoạch. Kiểm tra witness của từng ô có thể kết luận thay đổi hành vi cho toàn bộ không gian IPv4 stateless hỗ trợ, nhưng chỉ khi việc duyệt mọi ô hoàn thành. Quá `max_cells` trả INCONCLUSIVE.

**Q: Tại sao báo PASS của baseline không chứng minh an toàn?**

A: Vì chính sách baseline và tập quyền tham chiếu cùng sinh từ quyền được duyệt nên kiểm tra ở đây chỉ chứng minh tính nhất quán nội bộ. Để kiểm tra một chính sách nhập bên ngoài, dùng what-if so với entitlement và quyền đã duyệt; vẫn cần kiểm tra tính đúng đắn của yêu cầu nghiệp vụ.

**Q: Tại sao log Zeek không chứng minh firewall đã ALLOW?**

A: Vì Zeek ghi những kết nối quan sát tại điểm thu thập, không phải quyết định thực thi của thiết bị firewall. Cần log firewall đáng tin nếu muốn khẳng định hành động ALLOW/DENY thực sự.

**Q: “Logic mở” được thể hiện thế nào?**

A: Tạo tài nguyên và dịch vụ mới không sửa code; thêm role entitlement, phiếu và chính sách động; core độc lập FastAPI/web; exporter và parser có thể bổ sung; SQLite có thể thay bằng DB lớn hơn. Đề tài vẫn có giới hạn rõ ràng ở bản prototype.

**Q: Rủi ro lớn nhất của V2?**

A: Gắn quyền mạng với IP tĩnh có thể không chính xác trong doanh nghiệp DHCP/NAT/shared device. Giải pháp thực tế cần nguồn định danh thiết bị đáng tin, không coi IP là căn cứ xác thực người dùng.

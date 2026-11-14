
#!/bin/bash

MODE="$1"

case "$MODE" in
  deny|allow|revoke) ;;
  *)
    echo "Cach dung: ./demo.sh deny|allow|revoke"
    exit 1
    ;;
esac

# Kiem tra firewall lab
sudo ip netns exec fwlab nft list chain inet accessflow forward >/dev/null || exit 1

# Xoa luat thu nghiem cu
sudo ip netns exec fwlab nft flush chain inet accessflow forward || exit 1

# Cho phep goi tin phan hoi
sudo ip netns exec fwlab nft 'add rule inet accessflow forward ct state established,related accept' || exit 1

# Neu ALLOW thi them quyen Client -> CRM
if [ "$MODE" = "allow" ]; then
  sudo ip netns exec fwlab nft 'add rule inet accessflow forward ip saddr 10.10.30.10 ip daddr 10.20.4.20 tcp dport 443 ct state new accept' || exit 1
fi

echo "=============================="
echo "ACCESSFLOW LAB: $MODE"
echo "=============================="

# Thu truy cap dich vu CRM
if sudo ip netns exec client curl -I --max-time 5 http://10.20.4.20:443; then
  echo "KET QUA: KET NOI THANH CONG"
else
  echo "KET QUA: KHONG KET NOI DUOC"
fi

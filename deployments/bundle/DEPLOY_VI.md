# Triển khai WireGate technical POC

Bộ này dành cho gateway Linux `amd64` hoặc `arm64`, dùng:

- Agent native chạy `root` qua systemd và Unix socket.
- Web chạy Docker với UID/GID cố định, drop toàn bộ capabilities.
- TLS bắt buộc; không mở agent qua TCP.

## 1. Điều kiện máy đích

- Ubuntu/Debian dùng systemd, kernel có WireGuard.
- Docker Engine và Docker Compose v2.
- `wireguard-tools`, `iproute2`, `nftables`, `openssl`, `getent`, `groupadd`, `systemctl`.
- TCP `8443` được phép từ mạng quản trị.
- UDP port của WireGuard được cấu hình riêng theo interface hiện có.
- Không có WireGate cũ trên máy; installer fresh-host sẽ từ chối ghi đè.

Kiểm tra kiến trúc:

```bash
uname -m
# x86_64  -> dùng bundle linux-amd64
# aarch64 -> dùng bundle linux-arm64
```

## 2. Chép và kiểm tra bundle

```bash
scp wiregate-*-linux-amd64.tar.gz user@gateway:/tmp/
scp wiregate-*-linux-amd64.tar.gz.sha256 user@gateway:/tmp/
ssh user@gateway
cd /tmp
sha256sum -c wiregate-*-linux-amd64.tar.gz.sha256
tar -xzf wiregate-*-linux-amd64.tar.gz
cd wiregate-*-linux-amd64
sha256sum -c SHA256SUMS
```

## 3. Cài đặt

Với certificate có sẵn:

```bash
sudo ./install.sh \
  --public-host vpn-admin.example.com \
  --tls-cert /path/fullchain.pem \
  --tls-key /path/privkey.pem
```

Lab/LAN chưa có certificate:

```bash
sudo ./install.sh --public-host 192.168.1.10
```

Installer sẽ tạo self-signed certificate, build web image offline từ binary
trong bundle, chạy agent/web, đợi healthcheck và in bootstrap token 15 phút.

Nếu UID/GID `10001` đã bị dùng, chọn cặp chưa dùng:

```bash
sudo ./install.sh \
  --public-host 192.168.1.10 \
  --web-uid 12001 \
  --web-gid 12001
```

## 4. Tạo admin đầu tiên

Mở URL installer in ra, nhập bootstrap token, username và mật khẩu tối thiểu
12 ký tự. Token chỉ dùng một lần và hết hạn sau 15 phút.

## 5. Xác minh

```bash
sudo systemctl status wiregate-agent.socket wiregate-agent.service
sudo journalctl -u wiregate-agent.service -n 100 --no-pager

sudo docker compose \
  --env-file /etc/wiregate-web/runtime.env \
  -f /etc/wiregate-web/compose.yaml ps

curl -k https://127.0.0.1:8443/healthz
curl -k https://127.0.0.1:8443/readyz

sudo stat -c '%a %U:%G %n' \
  /etc/wiregate/keys \
  /etc/wiregate/keys/key-v0001.bin \
  /var/lib/wiregate-agent/agent.db \
  /var/lib/wiregate-web/web.db
```

Kỳ vọng:

- `healthz` và `readyz` trả HTTP 200.
- Agent và web đều healthy/active.
- Key directory `700`; key và database agent `600`.
- UI thấy các interface `wg-quick` trong `/etc/wireguard`.
- Chưa bấm Adopt trước khi xem preview, warnings và kiểm tra backup.

## 6. Backup bắt buộc

Dừng web/agent hoặc dùng SQLite backup nhất quán, rồi bảo vệ:

```text
/etc/wiregate/keys/
/etc/wiregate/agent.yaml
/var/lib/wiregate-agent/agent.db
/var/lib/wiregate-web/web.db
/etc/wiregate-web/tls/
/etc/wireguard/
```

Mất `/etc/wiregate/keys` đồng nghĩa không giải mã được secret đã lưu.

## 7. Gỡ cài đặt

Giữ nguyên config, keys, DB và tunnel:

```bash
sudo ./uninstall.sh
```

Xóa cả metadata/keys/DB phải xác nhận rõ:

```bash
sudo ./uninstall.sh --purge --confirm-purge
```

`purge` không xóa `/etc/wireguard`; hãy quản trị tunnel đó riêng.

## 8. Nâng cấp bản đang chạy

Kiểm tra checksum và giải nén bundle mới như mục 2, rồi chạy:

```bash
cd /tmp/wiregate-<version>-linux-<arch>
sudo ./upgrade.sh
```

Upgrade build image trước khi mở maintenance window, sau đó dừng ngắn web và
agent để sao lưu nhất quán. Backup gồm binary cũ, DB, keys, TLS và
`/etc/wireguard`, nằm tại `/var/backups/wiregate/upgrade-<timestamp>`.
Tunnel `wg-quick` đang hoạt động không bị stop; agent/web được thay độc lập với
data plane. Sau nâng cấp luôn kiểm tra `readyz`, container health và
`wg-quick@<interface>.service`.

## 9. Phạm vi POC

Bản này đã mở discovery/adoption UI, import IPAM và peer cũ có/không PSK,
greenfield interface, tạo peer managed/one-time/external, peer update, managed
export `.conf`/QR và lifecycle disable/enable/revoke. Các luồng này dùng
operation journal, revision/hash guard và đã qua adopt-only smoke + reboot gate
trên Ubuntu ARM64.

Interface start/stop UI, drift resolution, operation rollback UI và re-enroll
atomic vẫn fail-closed. nftables coexistence với mọi firewall manager và
AWS-equivalent traffic vẫn là integration gate trước production.

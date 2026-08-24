# WireGate

Repository được chia thành bốn vùng độc lập:

```text
.
├── src/          # Go, Protobuf, migrations, config mẫu và build scripts
├── build/        # Binary, cache/toolchain và release bundles sinh ra
├── deployments/  # Installer, Docker Compose/Dockerfile và systemd units
└── docs/          # Solution, SAD, DAD, phản biện và tài liệu dự án
```

## Kiểm tra và build

Từ thư mục gốc repository:

```bash
make -C src check
make -C src bundle
```

Binary cục bộ nằm trong `build/bin/`; bundle Linux `amd64` và `arm64` nằm
trong `build/releases/`.

## Tài liệu và triển khai

- Bắt đầu đọc tại [`docs/00_START_HERE.md`](docs/00_START_HERE.md).
- Trạng thái implementation tại [`docs/README.md`](docs/README.md).
- Hướng dẫn phase WireGuard có sẵn tại
  [`docs/ADOPT_ONLY_PHASE_VI.md`](docs/ADOPT_ONLY_PHASE_VI.md).
- Hướng dẫn deploy tại
  [`deployments/bundle/DEPLOY_VI.md`](deployments/bundle/DEPLOY_VI.md).
- Runbook VM test Multipass tại
  [`docs/MULTIPASS_LAB_VI.md`](docs/MULTIPASS_LAB_VI.md).

> Lưu ý: đây là technical POC. Phase adopt-only, import peer/IPAM, peer
> create/update/lifecycle và export/QR đã qua Ubuntu ARM64 smoke + reboot gate;
> các acceptance gate còn lại được ghi rõ trong tài liệu trạng thái.

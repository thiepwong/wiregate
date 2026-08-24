# Deployments

Thư mục này chứa các định nghĩa triển khai, không chứa artifact đã build:

- `bundle/`: installer fresh-host, Compose và Docker build context dùng trong
  release bundle.
- `docker/`: Dockerfiles và Compose manifests phục vụ phát triển/đánh giá.
- `systemd/`: socket, service và tmpfiles definition cho privileged agent.

Chạy `make -C src bundle` từ thư mục gốc để kết hợp source với các definition
này. Bundle đầu ra được ghi vào `build/releases/`.

Hướng dẫn cài bundle nằm tại [`bundle/DEPLOY_VI.md`](bundle/DEPLOY_VI.md).
Môi trường test macOS/Multipass hiện tại được ghi lại tại
[`../docs/MULTIPASS_LAB_VI.md`](../docs/MULTIPASS_LAB_VI.md).

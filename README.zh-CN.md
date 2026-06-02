# HeadStone1/s-ui 安全加固版

<p align="center">
  <a href="./README.md">English EN</a> /
  <a href="./README.zh-CN.md">简体中文 CN</a>
</p>

`HeadStone1/s-ui` 是基于 S-UI 继续维护的安全加固版本，保留原有 Sing-Box Web 面板能力，重点改进默认部署安全性和公网使用风险。

根据原 README 记录，本仓库复刻自 `alireza0/s-ui` 的 1.4.1 版本备份。

- 原作者项目：<https://github.com/alireza0/s-ui>
- 当前维护仓库：<https://github.com/HeadStone1/s-ui>

## 开源协议和免责声明

本项目沿用 GNU General Public License v3.0 开源协议，详情请查看 [LICENSE](./LICENSE)。

本项目仅供局域网学习、研究和技术交流使用，切勿用于任何非法用途。使用者应自行遵守所在地法律法规，并承担相应使用责任。

## 主要安全加固

### 账号和密码

- 移除默认 `admin/admin` 管理员口令。
- 首次启动自动生成随机管理员密码。
- 管理员重置命令不再回退到 `admin/admin`。
- 禁止将管理员凭据设置为 `admin/admin`。
- 管理员密码使用 bcrypt 哈希存储，不再明文保存。
- 登录校验使用哈希比对。
- 命令行查看管理员信息时不再显示真实密码。

### Web 登录态

- Session Cookie 启用 `HttpOnly`。
- Session Cookie 设置 `SameSite=Lax`。
- HTTPS 环境下启用 `Secure` Cookie。
- 登录后生成 CSRF Token。
- Cookie 登录态下的写操作需要 `X-CSRF-Token`。
- 前端请求会自动携带 CSRF Token。

### SQL 注入修复

- 修复变更查询中的 SQL 拼接问题。
- `CheckChanges` 使用数字解析和参数化查询。
- `GetChanges` 使用 GORM 参数绑定。
- 查询数量增加上限，避免异常大查询。

### 登录防爆破

- 登录失败按用户名和远程 IP 限制。
- 连续失败后临时锁定。
- 默认不信任客户端伪造的 `X-Forwarded-For`。

### API Token

- API Token 不再明文存储。
- 数据库只保存 Token Hash。
- Token 比对使用 constant-time 方式。
- Token 支持 `read`、`write`、`admin` 权限范围。
- Token 支持过期时间。
- 高危操作需要 `admin` 权限。

### 数据库导入导出

- Web 端数据库导出改为 POST 确认。
- Web 端导入和导出需要再次输入当前管理员密码。
- 导入数据库限制上传大小。
- 导入前校验 SQLite 文件头。
- 导入前自动备份。
- 导入成功后清理 API Token，并重新生成 Session Secret。

### 外链转换 SSRF 防护

- 仅允许 `http` 和 `https`。
- 禁止访问本机、内网、链路本地和未指定地址。
- DNS 解析后校验目标 IP。
- 跳转后的目标地址也会重新校验。
- 设置请求超时并限制响应体大小。
- 禁止 `file://`、`ftp://`、`gopher://` 等非 HTTP 协议。

### 订阅链接

- 订阅链接不再只依赖客户端名称。
- 客户端增加独立 `sub_secret`。
- 订阅 URL 使用客户端 ID 和随机 secret。
- 旧的仅客户端名称订阅路径不再返回订阅内容。

### Docker 和安装源

- 默认 Docker Compose 不再使用 host network。
- Docker 镜像使用非 root 用户 `sui`。
- Compose 启用 `read_only: true`。
- `/tmp` 使用 tmpfs。
- 镜像地址改为 `ghcr.io/headstone1/s-ui`。
- 安装脚本、更新脚本和 Release 下载地址改为 `HeadStone1/s-ui`。
- Go module 和内部 import 路径改为 `github.com/HeadStone1/s-ui`。
- Release 压缩包增加 sha256 校验。
- 文档不再推荐 `bash <(curl ...)` 安装方式。

## 部署方法

```sh
curl -fL -o install.sh https://raw.githubusercontent.com/HeadStone1/s-ui/main/install.sh
bash install.sh
```

安装完成后请保存终端输出的随机管理员密码，并尽快修改为自己的高强度密码。

## 部署建议

- 不建议将管理面板无保护地直接暴露到公网。
- 建议启用 HTTPS。
- 建议放在可信反向代理之后。
- 建议限制管理入口访问来源。
- 使用高强度管理员密码。
- 定期轮换 API Token。
- 定期备份并保护数据库文件。
- 定期更新镜像、二进制文件和依赖。

## 验证状态

当前版本已通过基础检查：

```sh
gofmt
go test ./...
git diff --check
```

Go 后端编译通过，仓库内已无 `admin8800` 残留。

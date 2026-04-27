# AiKey CLI

安全的本地密钥管理工具。管理 API Key 和 Provider OAuth 账号，通过本地代理（aikey-proxy）安全地转发请求。

详细英文文档见 [README.md](README.md)。

## 快速开始

```bash
# 添加单条 API Key（vault 会在首次使用时自动初始化）
aikey add my-claude --provider anthropic

# 从零散文本批量导入（浏览器 Web UI，完全本地）
aikey import                         # 打开空白粘贴页
aikey import ~/my-keys.txt           # 打开并预填文件路径

# 选择当前使用的 Key
aikey use my-claude

# 通过代理运行命令
aikey run -- claude
```

## Web UI（`aikey web`）

在默认浏览器中打开本地 User Console（由 `aikey-local-server` 提供服务，安装脚本
已自动启动）。Console 聚合了 vault 管理、OAuth 账号、Virtual Key、用量账本、
批量导入等页面，全程 `localhost`，不调外网。

```bash
aikey web                  # 打开默认首页
aikey web vault            # 跳转到 Personal Vault
aikey web import           # 跳转到 Bulk Import
aikey web --port 18090     # 强制指定本地端口
aikey web --json           # 仅输出 URL JSON，不启动浏览器
```

前置条件与下面的"批量导入"相同（`aikey-local-server` 需在运行）。

## 批量导入（`aikey import`）

一个本地 Web UI，把任意排版的凭证文本解析成草稿列表供你勾选入库。全程**离线**，
解析引擎（规则 v2 + CRF + Provider Fingerprint 三层）在本地运行，**不上传任何数据**。

### 前置条件
- 已执行 `local-install.sh` 或 `trial-install.sh`。安装脚本会写入端口文件
  `~/.aikey/config/local-server.port` 并启动 console 进程。
- `aikey status` 末尾显示 `local-server: running on port <p>` 一行即为正常。

如果 console 没有运行：
- **macOS**: `launchctl start com.aikey.local-server`
- **Linux**: `systemctl --user start aikey-local-server`
- **兜底**: `~/.aikey/bin/aikey-local-server --config ~/.aikey/config/control-trial.yaml &`

> 注：`aikey serve` / `aikey stop` 已移除，服务生命周期交给 launchctl / systemd 管理。

### 支持识别的格式
- 主流 provider 的 API Key 前缀：`sk-ant-api03-`、`sk-proj-`、`AIza`、`gsk_`、
  `ghp_`、`AKIA`、`SG.`、`eyJ…` 等 22 种 provider
- 邮箱 + 密码对（支持中英文字段标签：`email:` `邮箱:` `password:` `密码:`）
- OAuth handoff（Claude / Codex / Kimi）— UI 生成对应的
  `aikey auth login <provider>` 命令供你粘贴到 Terminal 执行
- 第三方网关的 `base_url`（比如 OpenAI 兼容端点）

### 隐私
页面顶部会持续显示 `OFFLINE · NOTHING LEAVES`。粘贴框里的原文只在浏览器和本地服务
进程内处理，不会发送到任何外网。vault 默认锁定，只有你点顶部 banner "Unlock"
输入主密码之后才能执行 Import。

## 用户配置文件

vault 之外，aikey 把运行时配置拆成系统态（installer 渲染）+ 用户态（`aikey-user.yaml`）两层。user 文件存放 trial 秘密 + admin email：

- Linux / macOS：`~/.aikey/config/aikey-user.yaml`
- Windows：`%LOCALAPPDATA%\Aikey\config\aikey-user.yaml`

仅首次 trial 安装（`trial-install.sh`）或 `local-install.sh --with-console` 时会创建。CLI / 纯 personal 安装不写 user 文件。

调整日志级别（不需要改 yaml）：

- `AIKEY_LOG_LEVEL=debug` —— trial server
- `AIKEY_PROXY_LOG_LEVEL=debug` —— aikey-proxy

完整设计：`roadmap20260320/技术实现/开源版本方案/config-split-system-user.md`

## Provider OAuth 账号 (`aikey auth`)

使用订阅套餐（Claude Pro/Max、ChatGPT Plus、Kimi Code）替代 API Key，通过 OAuth 授权登录。

```bash
# 登录 Provider（打开浏览器进行 OAuth 授权）
aikey auth login claude    # Claude Pro/Max — 粘贴回调页面的 code
aikey auth login codex     # ChatGPT Plus/Pro — 自动回调
aikey auth login kimi      # Kimi Code — 在浏览器输入设备码

# 查看 OAuth 账号
aikey auth list

# 设为当前活跃账号（替换该 Provider 的 API Key）
aikey auth use <account_id>

# 查看账号健康状态
aikey auth status <account_id>

# 登出
aikey auth logout <account_id>
```

支持的 Provider：

| Provider | 授权方式 | Token 有效期 | 订阅要求 |
|----------|---------|-------------|---------|
| Claude (Anthropic) | Setup Token（手动粘贴） | 1 年 | Pro/Max 订阅 |
| Codex (ChatGPT) | Auth Code（自动回调） | 10 天 | Plus/Pro（免费版也可用） |
| Kimi (Moonshot) | Device Code（轮询） | 15 分钟 | Coding Plan |

OAuth 和 API Key 在同一 Provider 内互斥——`aikey auth use` 会替换 `aikey use` 的绑定，反之亦然。

## 许可证

Apache-2.0

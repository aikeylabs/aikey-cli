# AiKey CLI

安全的本地密钥管理工具。管理 API Key 和 Provider OAuth 账号，通过本地代理（aikey-proxy）安全地转发请求。

详细英文文档见 [README.md](README.md)。

## 快速开始

```bash
# 添加 API Key（vault 会在首次使用时自动初始化）
aikey add my-claude --provider anthropic

# 选择当前使用的 Key
aikey use my-claude

# 通过代理运行命令
aikey run -- claude
```

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

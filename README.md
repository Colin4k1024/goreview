# GoReview

> AI-Powered Go Security & Performance Review

专为 Go 项目打造的 security + performance AI 审核工具。检测 Context 泄漏、Goroutine 泄漏、SQL 注入等通用工具扫不出的问题。

## 安装

```bash
go install github.com/goreview/cli@latest
```

## 快速开始

```bash
# 扫描当前项目
goreview scan ./...

# 只扫安全问题
goreview scan ./... --security

# 只扫性能问题
goreview scan ./... --performance

# 输出 JSON 格式
goreview scan ./... -o json

# 扫描私有仓库（需要 PRO）
goreview scan github.com/your/private-repo --token YOUR_GITHUB_TOKEN
```

## 检出问题类型

| 问题 | 严重度 | 说明 |
|------|--------|------|
| Context 泄漏 | 🔴 严重 | defer cancel 后 goroutine 继续使用已取消的 context |
| SQL 注入 | 🔴 严重 | 用字符串拼接 SQL 查询 |
| JWT 验证错误 | 🔴 严重 | 验证了签名但没有验证过期时间 |
| Goroutine 泄漏 | 🟡 中等 | 启动 goroutine 但没有优雅退出机制 |
| 敏感信息日志泄漏 | 🟡 中等 | Error log 里记录 token、password 等 |
| 资源未释放 | 🟡 中等 | database/sql、io.Closer 等没有正确关闭 |

## 定价

| 套餐 | 价格 | 功能 |
|------|------|------|
| Free | $0 | 公开仓库无限扫描，5 条规则 |
| Pro | $29/月 | 私有仓库，自定义规则，报告导出，历史趋势 |
| Team | $99/月 | 无限团队成员，SSO，SLA |

## 状态

🚧 工具开发中。第一版 CLI 预计 2026 年 Q2 发布。

## 联系方式

- GitHub Issues: https://github.com/goreview/cli/issues
- Email: hi@goreview.dev

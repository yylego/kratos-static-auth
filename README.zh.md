[![GitHub Workflow Status (branch)](https://img.shields.io/github/actions/workflow/status/yylego/kratos-static-auth/release.yml?branch=main&label=BUILD)](https://github.com/yylego/kratos-static-auth/actions/workflows/release.yml?query=branch%3Amain)
[![GoDoc](https://pkg.go.dev/badge/github.com/yylego/kratos-static-auth)](https://pkg.go.dev/github.com/yylego/kratos-static-auth)
[![Coverage Status](https://img.shields.io/coveralls/github/yylego/kratos-static-auth/main.svg)](https://coveralls.io/github/yylego/kratos-static-auth?branch=main)
[![Supported Go Versions](https://img.shields.io/badge/Go-1.25+-lightgrey.svg)](https://go.dev/)
[![GitHub Release](https://img.shields.io/github/release/yylego/kratos-static-auth.svg)](https://github.com/yylego/kratos-static-auth/releases)
[![Go Report Card](https://goreportcard.com/badge/github.com/yylego/kratos-static-auth)](https://goreportcard.com/report/github.com/yylego/kratos-static-auth)

# kratos-static-auth

静态令牌认证中间件，支持预配置的用户名-令牌映射。

---

<!-- TEMPLATE (ZH) BEGIN: LANGUAGE NAVIGATION -->

## 英文文档

[ENGLISH README](README.md)

<!-- TEMPLATE (ZH) END: LANGUAGE NAVIGATION -->

## 核心特性

🗺️ **令牌映射**: 基于预配置的用户名-令牌映射表进行认证
🔑 **多种格式**: 支持简单令牌、Bearer 令牌和 Base64 Basic Auth
👤 **用户名注入**: 认证成功后自动将用户名注入请求上下文
📡 **APM 追踪**: 通过 `authkratos.SpanHook` 进行可插拔的 span 钩子集成
⚙️ **路由范围**: 基于路由范围配置的选择性认证

## 安装

```bash
go get github.com/yylego/kratos-static-auth
```

## 使用方法

```go
import "github.com/yylego/kratos-static-auth/statickratosauth"

tokens := map[string]string{"admin": "secret-token-123"}
cfg := statickratosauth.NewConfig(routeScope, tokens).
    WithSimpleEnable().
    WithBearerEnable().
    WithBase64Enable()
mw := statickratosauth.NewMiddleware(cfg, logger)
```

---

<!-- TEMPLATE (ZH) BEGIN: STANDARD PROJECT FOOTER -->
<!-- VERSION 2025-11-25 03:52:28.131064 +0000 UTC -->

## 📄 许可证类型

MIT 许可证 - 详见 [LICENSE](LICENSE)。

---

## 💬 联系与反馈

非常欢迎贡献代码！报告 BUG、建议功能、贡献代码：

- 🐛 **问题报告？** 在 GitHub 上提交问题并附上重现步骤
- 💡 **新颖思路？** 创建 issue 讨论
- 📖 **文档疑惑？** 报告问题，帮助我们完善文档
- 🚀 **需要功能？** 分享使用场景，帮助理解需求
- ⚡ **性能瓶颈？** 报告慢操作，协助解决性能问题
- 🔧 **配置困扰？** 询问复杂设置的相关问题
- 📢 **关注进展？** 关注仓库以获取新版本和功能
- 🌟 **成功案例？** 分享这个包如何改善工作流程
- 💬 **反馈意见？** 欢迎提出建议和意见

---

## 🔧 代码贡献

新代码贡献，请遵循此流程：

1. **Fork**：在 GitHub 上 Fork 仓库（使用网页界面）
2. **克隆**：克隆 Fork 的项目（`git clone https://github.com/yourname/repo-name.git`）
3. **导航**：进入克隆的项目（`cd repo-name`）
4. **分支**：创建功能分支（`git checkout -b feature/xxx`）
5. **编码**：实现您的更改并编写全面的测试
6. **测试**：（Golang 项目）确保测试通过（`go test ./...`）并遵循 Go 代码风格约定
7. **文档**：面向用户的更改需要更新文档
8. **暂存**：暂存更改（`git add .`）
9. **提交**：提交更改（`git commit -m "Add feature xxx"`）确保向后兼容的代码
10. **推送**：推送到分支（`git push origin feature/xxx`）
11. **PR**：在 GitHub 上打开 Merge Request（在 GitHub 网页上）并提供详细描述

请确保测试通过并包含相关的文档更新。

---

## 🌟 项目支持

非常欢迎通过提交 Merge Request 和报告问题来贡献此项目。

**项目支持：**

- ⭐ **给予星标**如果项目对您有帮助
- 🤝 **分享项目**给团队成员和（golang）编程朋友
- 📝 **撰写博客**关于开发工具和工作流程 - 我们提供写作支持
- 🌟 **加入生态** - 致力于支持开源和（golang）开发场景

**祝你用这个包编程愉快！** 🎉🎉🎉

<!-- TEMPLATE (ZH) END: STANDARD PROJECT FOOTER -->

---

## GitHub 标星点赞

[![标星点赞](https://starchart.cc/yylego/kratos-static-auth.svg?variant=adaptive)](https://starchart.cc/yylego/kratos-static-auth)

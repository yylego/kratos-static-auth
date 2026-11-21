<!-- TEMPLATE (EN) BEGIN: BADGES -->

[![GitHub Workflow Status (branch)](https://img.shields.io/github/actions/workflow/status/yylego/kratos-static-auth/release.yml?branch=main&label=BUILD)](https://github.com/yylego/kratos-static-auth/actions/workflows/release.yml?query=branch%3Amain)
[![GoDoc](https://pkg.go.dev/badge/github.com/yylego/kratos-static-auth)](https://pkg.go.dev/github.com/yylego/kratos-static-auth)
[![Coverage Status](https://img.shields.io/coveralls/github/yylego/kratos-static-auth/main.svg)](https://coveralls.io/github/yylego/kratos-static-auth?branch=main)
[![Supported Go Versions](https://img.shields.io/badge/Go-1.26%2B-lightgrey.svg)](https://go.dev/)
[![GitHub Release](https://img.shields.io/github/release/yylego/kratos-static-auth.svg)](https://github.com/yylego/kratos-static-auth/releases)
[![Go Report Card](https://goreportcard.com/badge/github.com/yylego/kratos-static-auth)](https://goreportcard.com/report/github.com/yylego/kratos-static-auth)

<!-- TEMPLATE (EN) CLOSE: BADGES -->

# kratos-static-auth

Static token authentication middleware with pre-configured username-token mapping.

---

<!-- TEMPLATE (EN) BEGIN: LANGUAGE NAVIGATION -->

## CHINESE README

[中文说明](README.zh.md)

<!-- TEMPLATE (EN) CLOSE: LANGUAGE NAVIGATION -->

## Main Features

- 🗺️ **Token Mapping**: Pre-configured username-to-token map based authentication
- 🔑 **Multiple Formats**: Supports simple tokens, Bearer tokens, and Base64 Basic Auth
- 👤 **Username Injection**: Auto-injects authenticated username into request context
- 🪵 **Debug Logs**: Each route match and auth outcome goes to the logger at debug level, and the logger level decides if it shows
- ⚙️ **Route Scope**: Selective authentication based on route scope configuration

## Installation

```bash
go get github.com/yylego/kratos-static-auth
```

## Usage

```go
import (
    "log/slog"

    "github.com/go-kratos/kratos/v3/transport/http"
    "github.com/yylego/kratos-auth/authkratos"
    "github.com/yylego/kratos-static-auth/statickratosauth"
)

func newHTTPServer(logger *slog.Logger) *http.Server {
    // Check each route except the public ping
    routeScope := authkratos.NewExclude("/api.v1.Demo/Ping")
    // Username -> token
    tokens := map[string]string{"admin": "secret-token-123"}

    cfg := statickratosauth.NewConfig(routeScope, tokens).
        WithSimpleEnable(). // Authorization: secret-token-123
        WithBearerEnable(). // Authorization: Bearer secret-token-123
        WithBase64Enable()  // Authorization: Basic base64(admin:secret-token-123)

    return http.NewServer(
        http.Middleware(statickratosauth.NewMiddleware(cfg, logger)),
    )
}
```

`NewMiddleware` panics at startup on a wrong config, so it does not wait to show up as 401 on each request:

- No token type is enabled: enable at least one with `WithSimpleEnable`, `WithBearerEnable`, `WithBase64Enable`.
- A username has a blank token: it would let `Basic base64(admin:)` pass, which is a login with no password.
- Two usernames share one token, with at least one of `WithSimpleEnable`, `WithBearerEnable` in use: the token would map to just one of them, and which one changes from one startup to the next. The panic names the two usernames and leaves the token out.

A missing token and a token that matches nothing both get `401 UNAUTHORIZED` as the default. To respond with a custom reason, pass a `func(ctx context.Context) *errors.Error` to each of `WithMissingErk(newErk)` and `WithInvalidErk(newErk)`; write a log inside this function when one is wanted.

### Get the Username in Business Code

```go
func (s *DemoService) Admin(ctx context.Context, req *pb.AdminRequest) (*pb.AdminReply, error) {
    username, ok := statickratosauth.FromContext(ctx) // the username the token belongs to
    if !ok {
        return nil, errors.Unauthorized("UNAUTHORIZED", "no username in context")
    }
    return &pb.AdminReply{Message: "hello " + username}, nil
}
```

---

<!-- TEMPLATE (EN) BEGIN: STANDARD PROJECT FOOTER -->
<!-- VERSION 2025-11-25 03:52:28.131064 +0000 UTC -->

## 📄 License

MIT License - see [LICENSE](LICENSE).

---

## 💬 Contact & Feedback

Contributions are welcome! Report bugs, suggest features, and contribute code:

- 🐛 **Mistake reports?** Open an issue on GitHub with reproduction steps
- 💡 **Fresh ideas?** Create an issue to discuss
- 📖 **Documentation confusing?** Report it so we can improve
- 🚀 **Need new features?** Share the use cases to help us understand requirements
- ⚡ **Performance issue?** Help us optimize through reporting slow operations
- 🔧 **Configuration problem?** Ask questions about complex setups
- 📢 **Follow project progress?** Watch the repo to get new releases and features
- 🌟 **Success stories?** Share how this package improved the workflow
- 💬 **Feedback?** We welcome suggestions and comments

---

## 🔧 Development

New code contributions, follow this process:

1. **Fork**: Fork the repo on GitHub (using the webpage UI).
2. **Clone**: Clone the forked project (`git clone https://github.com/yourname/repo-name.git`).
3. **Navigate**: Navigate to the cloned project (`cd repo-name`)
4. **Branch**: Create a feature branch (`git checkout -b feature/xxx`).
5. **Code**: Implement the changes with comprehensive tests
6. **Testing**: (Golang project) Ensure tests pass (`go test ./...`) and follow Go code style conventions
7. **Documentation**: Update documentation to support client-facing changes
8. **Stage**: Stage changes (`git add .`)
9. **Commit**: Commit changes (`git commit -m "Add feature xxx"`) ensuring backward compatible code
10. **Push**: Push to the branch (`git push origin feature/xxx`).
11. **PR**: Open a merge request on GitHub (on the GitHub webpage) with detailed description.

Please ensure tests pass and include relevant documentation updates.

---

## 🌟 Support

Welcome to contribute to this project via submitting merge requests and reporting issues.

**Project Support:**

- ⭐ **Give GitHub stars** if this project helps you
- 🤝 **Share with teammates** and (golang) programming friends
- 📝 **Write tech blogs** about development tools and workflows - we provide content writing support
- 🌟 **Join the ecosystem** - committed to supporting open source and the (golang) development scene

**Have Fun Coding with this package!** 🎉🎉🎉

<!-- TEMPLATE (EN) CLOSE: STANDARD PROJECT FOOTER -->

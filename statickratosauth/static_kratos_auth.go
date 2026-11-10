// Package statickratosauth: Static token authentication middleware
// Provides out-of-box auth with username-token map and various token format support
// Supports simple tokens, authorization tokens, and Base64-encoded Basic Auth
// Auto-injects authenticated username into request context
//
// statickratosauth: 静态令牌认证中间件
// 提供开箱即用的认证功能，支持用户名-令牌映射和多种令牌格式
// 支持简单令牌、Bearer 令牌和 Base64 编码的 Basic Auth
// 自动将已认证的用户名注入请求上下文
package statickratosauth

import (
	"context"
	"fmt"
	"log/slog"
	"maps"
	"slices"

	"github.com/go-kratos/kratos/v3/errors"
	"github.com/go-kratos/kratos/v3/middleware"
	"github.com/go-kratos/kratos/v3/middleware/selector"
	"github.com/go-kratos/kratos/v3/transport"
	"github.com/yylego/kratos-auth/authkratos"
	"github.com/yylego/kratos-static-auth/internal/utils"
	"github.com/yylego/must"
)

// Config holds authentication middleware configuration
// Includes route scope, token map, and enabled token types
//
// Config 认证中间件配置
// 包含路由范围、令牌映射和启用的令牌类型
type Config struct {
	routeScope   *authkratos.RouteScope // Route scope config // 路由范围配置
	authTokens   map[string]string      // Username to token map // 用户名到令牌的映射
	fieldName    string                 // Request field name // 请求头字段名
	simpleEnable bool                   // Enable simple token type // 启用简单令牌类型
	bearerEnable bool                   // Enable Bearer token type // 启用 Bearer 令牌类型
	base64Enable bool                   // Enable Base64 Basic Auth type // 启用 Base64 Basic Auth 类型
}

// NewConfig creates a new Config with route scope and token map
// Default: field name "Authorization", no token type enabled yet
//
// NewConfig 创建新的配置，包含路由范围和令牌映射
// 默认字段名 "Authorization"，还没有启用任何令牌类型
func NewConfig(
	routeScope *authkratos.RouteScope,
	authTokens map[string]string,
) *Config {
	return &Config{
		// Avoid non-standard field names
		// Nginx ignores names with underscores unless underscores_in_headers is on
		// Recommend avoiding names with non-standard chars
		//
		// 避免非标准字段名
		// Nginx 默认忽略带下划线的 headers，除非配置 underscores_in_headers on
		// 建议不用含特殊字符的字段名
		routeScope: routeScope,
		authTokens: authTokens,
		fieldName:  "Authorization",
	}
}

// WithFieldName sets request field name used in authentication
// Avoid non-standard names in configuration
// Nginx ignores names with underscores unless underscores_in_headers is on
// Recommend not using names with extra punctuation in development
//
// WithFieldName 设置请求头中用于认证的字段名
// 注意配置时不要配置非标准的字段名
// Nginx 默认忽略带有下划线的 headers 信息，除非配置 underscores_in_headers on
// 因此在开发中建议不要配置含特殊字符的字段名
func (c *Config) WithFieldName(fieldName string) *Config {
	c.fieldName = fieldName
	return c
}

// GetFieldName gets request field name used in authentication
//
// GetFieldName 获取请求头中用于认证的字段名
func (c *Config) GetFieldName() string {
	return c.fieldName
}

// WithSimpleEnable enables simple token type authentication
// Token format: "secret-token-123"
//
// WithSimpleEnable 启用简单令牌类型认证
// 令牌格式: "secret-token-123"
func (c *Config) WithSimpleEnable() *Config {
	c.simpleEnable = true
	return c
}

// WithBearerEnable enables Bearer token type authentication
// Token format: "Bearer secret-token-123"
//
// WithBearerEnable 启用 Bearer 令牌类型认证
// 令牌格式: "Bearer secret-token-123"
func (c *Config) WithBearerEnable() *Config {
	c.bearerEnable = true
	return c
}

// WithBase64Enable enables Base64 Basic Auth type authentication
// Token format: "Basic base64(username:password)"
//
// WithBase64Enable 启用 Base64 Basic Auth 类型认证
// 令牌格式: "Basic base64(username:password)"
func (c *Config) WithBase64Enable() *Config {
	c.base64Enable = true
	return c
}

// GetSimpleTokens returns username to token map
// Returns nil if Config is nil
//
// GetSimpleTokens 返回用户名到令牌的映射
// Config 为 nil 时返回 nil
func (c *Config) GetSimpleTokens() map[string]string {
	if c != nil {
		return c.authTokens
	}
	return nil
}

// GetBase64Tokens returns username to Basic Auth token map
//
// GetBase64Tokens 返回用户名到 Basic Auth 令牌的映射
func (c *Config) GetBase64Tokens() map[string]string {
	var res = make(map[string]string, len(c.GetSimpleTokens()))
	for username, password := range c.GetSimpleTokens() {
		res[username] = utils.BasicAuth(username, password)
	}
	return res
}

// LookupBase64Token picks Basic Auth token by username
// Panics if username not found in token map
//
// LookupBase64Token 根据用户名挑选 Basic Auth 令牌
// 用户名不存在时 panic
func (c *Config) LookupBase64Token(username string) string {
	password, ok := c.GetSimpleTokens()[username]
	must.TRUE(ok)
	must.Nice(password)
	return utils.BasicAuth(username, password)
}

// RandomBase64Token returns a random Basic Auth token from token map
//
// RandomBase64Token 从令牌映射中随机返回一个 Basic Auth 令牌
func (c *Config) RandomBase64Token() string {
	return c.LookupBase64Token(utils.Sample(slices.Collect(maps.Keys(c.GetSimpleTokens()))))
}

// NewMiddleware creates authentication middleware with config and logger
// Uses selector.Server to match routes and check auth tokens
// Panics when no token type is enabled, and also when a username comes with a blank token
// Each match and each auth outcome goes to applog at debug level, so the level of applog decides if it shows
//
// NewMiddleware 使用配置和日志创建认证中间件
// 使用 selector.Server 匹配路由并检查认证令牌
// 没有启用任何令牌类型、或有用户的令牌为空时 panic
// 每次匹配和每次认证结果都以 debug 级别写进 applog，显示与否由 applog 的日志级别决定
func NewMiddleware(cfg *Config, applog *slog.Logger) middleware.Middleware {
	// A wrong config shows up at startup, not as 401 on each request
	// 配置写错在启动时就暴露，而不是每个请求都返回 401
	if !cfg.simpleEnable && !cfg.bearerEnable && !cfg.base64Enable {
		panic(fmt.Errorf("static-kratos-auth: no token type enabled, enable one with WithSimpleEnable, WithBearerEnable, WithBase64Enable"))
	}
	for username, token := range cfg.authTokens {
		// A blank token lets "Basic base64(username:)" pass, which is a login with no password
		// 空令牌会让 "Basic base64(用户名:)" 通过，等于不用密码就能登录
		if token == "" {
			panic(fmt.Errorf("static-kratos-auth: username %q has a blank token", username))
		}
	}

	applog.Info(
		"static-kratos-auth: new middleware",
		"field-name", cfg.fieldName,
		"auth-tokens", len(cfg.authTokens),
		"side", cfg.routeScope.Side,
		"operations", len(cfg.routeScope.OperationSet),
		"simple-enable", cfg.simpleEnable,
		"bearer-enable", cfg.bearerEnable,
		"base64-enable", cfg.base64Enable,
	)
	applog.Debug("static-kratos-auth: new middleware route-scope", "route-scope", cfg.routeScope)
	return selector.Server(middlewareFunc(cfg, applog)).Match(matchFunc(cfg, applog)).Build()
}

// matchFunc creates route matching function
// Returns true if operation should be authenticated
//
// matchFunc 创建路由匹配函数
// 操作需要认证时返回 true
func matchFunc(cfg *Config, applog *slog.Logger) selector.MatchFunc {
	return func(ctx context.Context, operation string) bool {
		match := cfg.routeScope.Match(operation)
		applog.Debug("static-kratos-auth: route match", "operation", operation, "side", cfg.routeScope.Side, "match", match)
		return match
	}
}

// middlewareFunc creates authentication middleware implementation
// Validates tokens and injects username into context
//
// middlewareFunc 创建实际的认证中间件
// 验证令牌并将用户名注入 context
func middlewareFunc(cfg *Config, applog *slog.Logger) middleware.Middleware {
	// Build token maps based on enabled types, init blank maps as default
	// 根据启用的类型构建令牌映射，默认初始化空 map
	mapBox := &authTokenMapBox{
		simpleTokenMap: make(map[string]string),
		bearerTokenMap: make(map[string]string),
		base64TokenMap: make(map[string]string),
	}
	if cfg.simpleEnable {
		mapBox.simpleTokenMap = newSimpleTokenMap(cfg.authTokens)
	}
	if cfg.bearerEnable {
		mapBox.bearerTokenMap = newBearerTokenMap(cfg.authTokens)
	}
	if cfg.base64Enable {
		mapBox.base64TokenMap = newBase64TokenMap(cfg.authTokens)
	}

	return func(handleFunc middleware.Handler) middleware.Handler {
		return func(ctx context.Context, req any) (any, error) {
			tsp, ok := transport.FromServerContext(ctx)
			if !ok {
				return nil, errors.Unauthorized("UNAUTHORIZED", "static-kratos-auth: wrong context")
			}
			authToken := tsp.RequestHeader().Get(cfg.fieldName)
			if authToken == "" {
				applog.Debug("static-kratos-auth: auth-token is missing")
				return nil, errors.Unauthorized("UNAUTHORIZED", "static-kratos-auth: auth-token is missing")
			}
			username, erk := checkAuthToken(mapBox, authToken, applog)
			if erk != nil {
				applog.Debug("static-kratos-auth: auth-token mismatch", "reason", erk.Error())
				return nil, erk
			}
			// Auth success, inject username into context
			// Business code can get username via GetUsername(ctx)
			//
			// 认证成功，将用户名注入 context
			// 业务代码可通过 GetUsername(ctx) 获取用户名
			return handleFunc(SetUsername(ctx, username), req)
		}
	}
}

// checkAuthToken validates token against enabled token maps
// Returns username on success, error on failure
//
// checkAuthToken 根据启用的令牌映射验证令牌
// 成功返回用户名，失败返回错误
func checkAuthToken(mapBox *authTokenMapBox, token string, applog *slog.Logger) (string, *errors.Error) {
	if username, ok := mapBox.simpleTokenMap[token]; ok {
		applog.Debug("static-kratos-auth: simple-type request quick pass", "username", username)
		return username, nil
	}
	if username, ok := mapBox.bearerTokenMap[token]; ok {
		applog.Debug("static-kratos-auth: bearer-type request quick pass", "username", username)
		return username, nil
	}
	if username, ok := mapBox.base64TokenMap[token]; ok {
		applog.Debug("static-kratos-auth: base64-type request quick pass", "username", username)
		return username, nil
	}
	return "", errors.Unauthorized("UNAUTHORIZED", "static-kratos-auth: auth-token mismatch")
}

// authTokenMapBox holds pre-built token to username maps
// Each map type is built based on enabled token types
//
// authTokenMapBox 保存预构建的令牌到用户名映射
// 每种映射根据启用的令牌类型构建
type authTokenMapBox struct {
	simpleTokenMap map[string]string // Token -> username // 令牌 -> 用户名
	bearerTokenMap map[string]string // "Bearer token" -> username // "Bearer 令牌" -> 用户名
	base64TokenMap map[string]string // "Basic base64" -> username // "Basic base64" -> 用户名
}

// newSimpleTokenMap builds simple token to username map
// Maps raw token to username
//
// newSimpleTokenMap 构建简单令牌到用户名的映射
// 将原始令牌映射到用户名
func newSimpleTokenMap(usernameToTokenMap map[string]string) map[string]string {
	simpleTypeToUsername := make(map[string]string, len(usernameToTokenMap))
	for username, token := range usernameToTokenMap {
		simpleTypeToUsername[token] = username
	}
	return simpleTypeToUsername
}

// newBearerTokenMap builds Bearer token to username map
// Maps "Bearer {token}" to username
//
// newBearerTokenMap 构建 Bearer 令牌到用户名的映射
// 将 "Bearer {令牌}" 映射到用户名
func newBearerTokenMap(usernameToTokenMap map[string]string) map[string]string {
	bearerTypeToUsername := make(map[string]string, len(usernameToTokenMap))
	for username, token := range usernameToTokenMap {
		bearerTypeToUsername["Bearer "+token] = username
	}
	return bearerTypeToUsername
}

// newBase64TokenMap builds Base64 Basic Auth token to username map
// Maps "Basic {base64(username:password)}" to username
//
// newBase64TokenMap 构建 Base64 Basic Auth 令牌到用户名的映射
// 将 "Basic {base64(用户名:密码)}" 映射到用户名
func newBase64TokenMap(usernameToTokenMap map[string]string) map[string]string {
	base64TypeToUsername := make(map[string]string, len(usernameToTokenMap))
	for username, token := range usernameToTokenMap {
		base64TypeToUsername[utils.BasicAuth(username, token)] = username
	}
	return base64TypeToUsername
}

// usernameKey is context key type used to store username
//
// usernameKey 是用于存储用户名的 context key 类型
type usernameKey struct{}

// SetUsername puts the username into the context
// The middleware calls it on auth success, so business code can read the username with GetUsername
//
// SetUsername 把用户名放进 context
// 认证成功时中间件会调用它，业务代码再用 GetUsername 取出用户名
func SetUsername(ctx context.Context, username string) context.Context {
	return context.WithValue(ctx, usernameKey{}, username)
}

// GetUsername reads the username from the context, with a flag that tells if it is there
//
// GetUsername 从 context 取出用户名，并返回是否取到
func GetUsername(ctx context.Context) (string, bool) {
	username, ok := ctx.Value(usernameKey{}).(string)
	return username, ok
}

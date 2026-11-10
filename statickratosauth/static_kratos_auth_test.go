package statickratosauth

import (
	"bytes"
	"context"
	"log/slog"
	"testing"

	"github.com/go-kratos/kratos/v3/errors"
	"github.com/go-kratos/kratos/v3/transport"
	"github.com/stretchr/testify/require"
	"github.com/yylego/kratos-auth/authkratos"
)

// mockHeader is a map-backed transport.Header
// mockHeader 是用 map 实现的 transport.Header
type mockHeader map[string]string

func (m mockHeader) Get(name string) string        { return m[name] }
func (m mockHeader) Set(name string, value string) { m[name] = value }
func (m mockHeader) Add(name string, value string) { m[name] = value }
func (m mockHeader) Values(name string) []string   { return []string{m[name]} }
func (m mockHeader) Keys() []string {
	names := make([]string, 0, len(m))
	for name := range m {
		names = append(names, name)
	}
	return names
}

// mockTransport is a stub transport.Transporter on the service side, carrying the operation and the request header
// mockTransport 是服务端 transport.Transporter 的桩，带着接口名和请求头
type mockTransport struct {
	operation string
	header    mockHeader
}

func (t *mockTransport) Kind() transport.Kind            { return transport.KindHTTP }
func (t *mockTransport) Endpoint() string                { return "" }
func (t *mockTransport) Operation() string               { return t.operation }
func (t *mockTransport) RequestHeader() transport.Header { return t.header }
func (t *mockTransport) ReplyHeader() transport.Header   { return mockHeader{} }

const (
	operationPing  = "/api.v1.Demo/Ping"
	operationAdmin = "/api.v1.Demo/Admin"
)

// runWithToken runs the middleware on one request and returns the username the handle func sees
// runWithToken 用中间件处理一次请求，返回 handle 函数看到的用户名
func runWithToken(t *testing.T, cfg *Config, operation string, token string) (string, error) {
	handle := NewMiddleware(cfg, slog.New(slog.DiscardHandler))(func(ctx context.Context, req any) (any, error) {
		username, _ := GetUsername(ctx)
		return username, nil
	})
	header := mockHeader{}
	if token != "" {
		header[cfg.GetFieldName()] = token
	}
	ctx := transport.NewServerContext(context.Background(), &mockTransport{operation: operation, header: header})
	reply, err := handle(ctx, nil)
	if err != nil {
		return "", err
	}
	return reply.(string), nil
}

func TestNewMiddleware(t *testing.T) {
	tokens := map[string]string{"admin": "secret-token-123", "guest": "guest-token-456"}
	cfg := NewConfig(authkratos.NewExclude(operationPing), tokens).
		WithSimpleEnable().
		WithBearerEnable().
		WithBase64Enable()

	t.Run("simple token", func(t *testing.T) {
		username, err := runWithToken(t, cfg, operationAdmin, "secret-token-123")
		require.NoError(t, err)
		require.Equal(t, "admin", username)
	})

	t.Run("bearer-type token", func(t *testing.T) {
		username, err := runWithToken(t, cfg, operationAdmin, "Bearer guest-token-456")
		require.NoError(t, err)
		require.Equal(t, "guest", username)
	})

	t.Run("basic auth token", func(t *testing.T) {
		username, err := runWithToken(t, cfg, operationAdmin, cfg.LookupBase64Token("guest"))
		require.NoError(t, err)
		require.Equal(t, "guest", username)
	})

	t.Run("missing token", func(t *testing.T) {
		_, err := runWithToken(t, cfg, operationAdmin, "")
		require.True(t, errors.IsUnauthorized(err))
	})

	t.Run("wrong token", func(t *testing.T) {
		_, err := runWithToken(t, cfg, operationAdmin, "Bearer not-a-token")
		require.True(t, errors.IsUnauthorized(err))
	})

	t.Run("excluded operation skips the check", func(t *testing.T) {
		username, err := runWithToken(t, cfg, operationPing, "")
		require.NoError(t, err)
		require.Equal(t, "", username)
	})
}

// TestNewMiddleware_SimpleType checks a format that is not enabled does not pass
// TestNewMiddleware_SimpleType 检查没有启用的格式不能通过
func TestNewMiddleware_SimpleType(t *testing.T) {
	cfg := NewConfig(authkratos.NewInclude(operationAdmin), map[string]string{"admin": "secret-token-123"}).
		WithSimpleEnable()

	username, err := runWithToken(t, cfg, operationAdmin, "secret-token-123")
	require.NoError(t, err)
	require.Equal(t, "admin", username)

	_, err = runWithToken(t, cfg, operationAdmin, "Bearer secret-token-123")
	require.True(t, errors.IsUnauthorized(err))
}

// TestNewMiddleware_BlankToken checks a blank token stops the startup
// It would pass as "Basic base64(admin:)", a login with no password
//
// TestNewMiddleware_BlankToken 检查有用户令牌为空时启动就 panic
// 否则这个用户可以用 "Basic base64(admin:)" 登录，等于不用密码
func TestNewMiddleware_BlankToken(t *testing.T) {
	cfg := NewConfig(authkratos.NewInclude(operationAdmin), map[string]string{"admin": ""}).
		WithBase64Enable()

	require.Panics(t, func() {
		NewMiddleware(cfg, slog.New(slog.DiscardHandler))
	})
}

// TestNewMiddleware_NoTypeEnabled checks a config with no token type enabled stops the startup
// TestNewMiddleware_NoTypeEnabled 检查没有启用任何令牌类型时启动就 panic
func TestNewMiddleware_NoTypeEnabled(t *testing.T) {
	cfg := NewConfig(authkratos.NewInclude(operationAdmin), map[string]string{"admin": "secret-token-123"})

	require.Panics(t, func() {
		NewMiddleware(cfg, slog.New(slog.DiscardHandler))
	})
}

func TestNewConfig(t *testing.T) {
	cfg := NewConfig(authkratos.NewInclude(operationAdmin), map[string]string{"admin": "secret-token-123"})
	require.Equal(t, "Authorization", cfg.GetFieldName())
	require.False(t, cfg.simpleEnable)
	require.False(t, cfg.bearerEnable)
	require.False(t, cfg.base64Enable)
}

func TestConfig_WithFieldName(t *testing.T) {
	cfg := NewConfig(authkratos.NewInclude(operationAdmin), map[string]string{"admin": "secret-token-123"}).
		WithFieldName("X-Token").
		WithSimpleEnable()

	username, err := runWithToken(t, cfg, operationAdmin, "secret-token-123")
	require.NoError(t, err)
	require.Equal(t, "admin", username)
}

func TestConfig_GetFieldName(t *testing.T) {
	cfg := NewConfig(authkratos.NewInclude(operationAdmin), map[string]string{"admin": "secret-token-123"})
	require.Equal(t, "Authorization", cfg.GetFieldName())
	require.Equal(t, "X-Token", cfg.WithFieldName("X-Token").GetFieldName())
}

func TestConfig_WithSimpleEnable(t *testing.T) {
	cfg := NewConfig(authkratos.NewInclude(operationAdmin), map[string]string{"admin": "secret-token-123"}).WithSimpleEnable()

	username, err := runWithToken(t, cfg, operationAdmin, "secret-token-123")
	require.NoError(t, err)
	require.Equal(t, "admin", username)
	_, err = runWithToken(t, cfg, operationAdmin, "Bearer secret-token-123")
	require.True(t, errors.IsUnauthorized(err))
}

func TestConfig_WithBearerEnable(t *testing.T) {
	cfg := NewConfig(authkratos.NewInclude(operationAdmin), map[string]string{"admin": "secret-token-123"}).WithBearerEnable()

	username, err := runWithToken(t, cfg, operationAdmin, "Bearer secret-token-123")
	require.NoError(t, err)
	require.Equal(t, "admin", username)
	_, err = runWithToken(t, cfg, operationAdmin, "secret-token-123")
	require.True(t, errors.IsUnauthorized(err))
}

func TestConfig_WithBase64Enable(t *testing.T) {
	cfg := NewConfig(authkratos.NewInclude(operationAdmin), map[string]string{"admin": "secret-token-123"}).WithBase64Enable()

	username, err := runWithToken(t, cfg, operationAdmin, "Basic YWRtaW46c2VjcmV0LXRva2VuLTEyMw==") // base64("admin:secret-token-123")
	require.NoError(t, err)
	require.Equal(t, "admin", username)
	_, err = runWithToken(t, cfg, operationAdmin, "secret-token-123")
	require.True(t, errors.IsUnauthorized(err))
}

func TestConfig_GetSimpleTokens(t *testing.T) {
	tokens := map[string]string{"admin": "secret-token-123"}
	require.Equal(t, tokens, NewConfig(authkratos.NewInclude(operationAdmin), tokens).GetSimpleTokens())

	var cfg *Config
	require.Nil(t, cfg.GetSimpleTokens())
}

func TestConfig_GetBase64Tokens(t *testing.T) {
	cfg := NewConfig(authkratos.NewInclude(operationAdmin), map[string]string{"admin": "secret-token-123"})
	require.Equal(t, map[string]string{"admin": "Basic YWRtaW46c2VjcmV0LXRva2VuLTEyMw=="}, cfg.GetBase64Tokens())
}

func TestConfig_LookupBase64Token(t *testing.T) {
	cfg := NewConfig(authkratos.NewInclude(operationAdmin), map[string]string{"admin": "secret-token-123"})
	require.Equal(t, "Basic YWRtaW46c2VjcmV0LXRva2VuLTEyMw==", cfg.LookupBase64Token("admin"))
	require.Panics(t, func() { cfg.LookupBase64Token("guest") })
}

func TestConfig_RandomBase64Token(t *testing.T) {
	cfg := NewConfig(authkratos.NewInclude(operationAdmin), map[string]string{"admin": "secret-token-123"})
	require.Equal(t, "Basic YWRtaW46c2VjcmV0LXRva2VuLTEyMw==", cfg.RandomBase64Token())
}

func TestSetUsername(t *testing.T) {
	username, ok := GetUsername(SetUsername(context.Background(), "admin"))
	require.True(t, ok)
	require.Equal(t, "admin", username)
}

func TestGetUsername(t *testing.T) {
	username, ok := GetUsername(context.Background())
	require.False(t, ok)
	require.Equal(t, "", username)
}

// TestNewMiddleware_DebugLogs checks the debug logs show at debug level and are hidden at info level
// TestNewMiddleware_DebugLogs 检查调试日志在 debug 级别显示、在 info 级别不显示
func TestNewMiddleware_DebugLogs(t *testing.T) {
	collectLogs := func(level slog.Level) string {
		var output bytes.Buffer
		logger := slog.New(slog.NewTextHandler(&output, &slog.HandlerOptions{
			Level: level,
			ReplaceAttr: func(groups []string, attr slog.Attr) slog.Attr {
				if attr.Key == slog.TimeKey {
					return slog.Attr{} // Drop the time so the output stays the same on each run // 去掉时间，每次输出才一样
				}
				return attr
			},
		}))
		cfg := NewConfig(authkratos.NewInclude(operationAdmin), map[string]string{"admin": "secret-token-123"}).WithSimpleEnable()
		handle := NewMiddleware(cfg, logger)(func(ctx context.Context, req any) (any, error) {
			return nil, nil
		})
		ctx := transport.NewServerContext(context.Background(), &mockTransport{operation: operationAdmin, header: mockHeader{"Authorization": "secret-token-123"}})
		_, err := handle(ctx, nil)
		require.NoError(t, err)
		return output.String()
	}

	require.Equal(t, `level=INFO msg="static-kratos-auth: new middleware" field-name=Authorization auth-tokens=1 side=INCLUDE operations=1 simple-enable=true bearer-enable=false base64-enable=false
`, collectLogs(slog.LevelInfo))

	require.Equal(t, `level=INFO msg="static-kratos-auth: new middleware" field-name=Authorization auth-tokens=1 side=INCLUDE operations=1 simple-enable=true bearer-enable=false base64-enable=false
level=DEBUG msg="static-kratos-auth: new middleware route-scope" route-scope="&{Side:INCLUDE OperationSet:map[/api.v1.Demo/Admin:true]}"
level=DEBUG msg="static-kratos-auth: route match" operation=/api.v1.Demo/Admin side=INCLUDE match=true
level=DEBUG msg="static-kratos-auth: simple-type request quick pass" username=admin
`, collectLogs(slog.LevelDebug))
}

### 基于OAuth2协议和JWT实现简单的认证和授权系统

```go
任务:  1.通过授权服务器 颁发 和 验证 访问令牌

      2. 通过资源服务器 对用户的授权资源进行保护
```

### 1.系统整体架构

```go
客户端访问资源服务器中用户持有的资源信息
1. 携带 用户凭证 向授权服务器 请求访问令牌
2. 授权服务器验证 客户端 和 用户凭证的有效性 返回生成的访问令牌给客户端
3. 客户端 携带 访问令牌 向资源服务器 请求对应的用户资源
4. 资源服务器 验证令牌
5. 资源服务器 根据令牌的时效性 返回受限资源
```

###  2.授权服务器

```go
功能: 颁发访问令牌  验证访问令牌
	/oauth/token  /oauth/check_token

实现模块： ClientDetailService 获取客户端信息
		 UserDetailService   获取用户信息
		 TokenGrant          根据授权类型进行不同的验证
				|
          TokenService        生成并管理令牌  用TokenStore存储
				|
		 TokenStore          负责令牌存储工作

```

#### 2.1 用户服务和客户端服务

```go
1. 定义用户信息和客户端信息结构体
model层 	model/user.go   client.go

2.UserDetailService 和ClientDetailService 根据对应的id或者用户名密码加载信息和方法
type ClientDetailsService interface {
    // Get ClientDetails By clientId
	GetClientDetailByClientId(ctx context.Context, clientId string, clientSecret string)(*model.ClientDetails, error)
}

type UserDetailsService interface {
	// Get UserDetails By username
	GetUserDetailByUsername(ctx context.Context, username, password string) (*model.UserDetails, error)
}
```

```go
3. 实现接口 即可以通过多种来源获取 用户信息和客户端信息
		   例子： 通过内存实现

即
//UserService implement Service interface
type InMemoryUserDetailsService struct {
	userDetailsDict map[string]*model.UserDetails

}

// 实现接口
func (service *InMemoryUserDetailsService) GetUserDetailByUsername(ctx context.Context, username, password string) (*model.UserDetails, error) {


	// 根据 username 获取用户信息
	userDetails, ok := service.userDetailsDict[username]; if ok{
		// 比较 password 是否匹配
		if userDetails.Password == password{
			return userDetails, nil
		}else {
			return nil, ErrPassword
		}
	}else {
		return nil, ErrUserNotExist
	}


}

// 内存存储服务
func NewInMemoryUserDetailsService(userDetailsList []*model.UserDetails) *InMemoryUserDetailsService {
	userDetailsDict := make(map[string]*model.UserDetails)

	if userDetailsList != nil {
		for _, value := range userDetailsList {
			userDetailsDict[value.Username] = value
		}
	}

	return &InMemoryUserDetailsService{
		userDetailsDict:userDetailsDict,
	}
}

client端与其类似 不做过多赘述
```

#### 2.2 TokenGrant令牌生成器

```go
根据 授权类型 不同对用户和客户端信息进行验证  认证成功生成并返回令牌
	GrantType
1.service层 token_service.go

type TokenGranter interface {
	Grant(ctx context.Context, grantType string, client *ClientDetails, reader *http.Request) (*OAuth2Token, error)
}

2.使用组合模式 使得 不同的授权类型 使用不同的TokenGranter接口实现结构体 来生成访问令牌
即ComposeTokenGranter
type ComposeTokenGranter struct {
	TokenGrantDict map[string] TokenGranter
}
即组合模式来对不同授权类型进行Grant
func (tokenGranter *ComposeTokenGranter) Grant(ctx context.Context, grantType string, client *ClientDetails, reader *http.Request) (*OAuth2Token, error) {

	dispatchGranter := tokenGranter.TokenGrantDict[grantType]

	if dispatchGranter == nil{
		return nil, ErrNotSupportGrantType
	}

	return dispatchGranter.Grant(ctx, grantType, client, reader)
}

3.对客户端携带的用户名和密码进行校验
UsernamePasswrordTokenGranter 密码类型的TokenGranter接口实现结构体的代码

func (tokenGranter *UsernamePasswordTokenGranter) Grant(ctx context.Context,
	grantType string, client *ClientDetails, reader *http.Request) (*OAuth2Token, error) {
	if grantType != tokenGranter.supportGrantType{
		return nil, ErrNotSupportGrantType
	}
	// 1.从请求体中获取用户名密码
	username := reader.FormValue("username")
	password := reader.FormValue("password")

	if username == "" || password == ""{
		return nil, ErrInvalidUsernameAndPasswordRequest
	}

	// 2.验证用户名密码是否正确
	userDetails, err := tokenGranter.userDetailsService.GetUserDetailByUsername(ctx, username, password)

	if err != nil{
		return nil, ErrInvalidUsernameAndPasswordRequest
	}

	// 3.根据用户信息和客户端信息生成访问令牌
	return tokenGranter.tokenService.CreateAccessToken(&OAuth2Details{
		Client:client,
		User:userDetails,

	})

}


4. 把令牌刷新的相关逻辑封装到RefreshTokenGranter中
func (tokenGranter *RefreshTokenGranter) Grant(ctx context.Context, grantType string, client *ClientDetails, reader *http.Request) (*OAuth2Token, error) {
	if grantType != tokenGranter.supportGrantType{
		return nil, ErrNotSupportGrantType
	}
	// 从请求中获取刷新令牌的请求参数
	refreshTokenValue := reader.URL.Query().Get("refresh_token")

	if refreshTokenValue == ""{
		return nil, ErrInvalidTokenRequest
	}
	
    // 刷新令牌获取 访问令牌 和刷新令牌
	return tokenGranter.tokenService.RefreshAccessToken(refreshTokenValue)

}

```

#### 2.3 TokenService 令牌服务

```go
1. 先查看令牌结构体OAuth2Token中携带的信息
   model/token.go

type OAuth2Token struct {
	// 刷新令牌
	RefreshToken *OAuth2Token
	// 令牌类型
	TokenType string
	// 令牌
	TokenValue string
	// 过期时间
	ExpiresTime *time.Time
}


func (oauth2Token *OAuth2Token) IsExpired() bool  {
	return oauth2Token.ExpiresTime != nil &&
		oauth2Token.ExpiresTime.Before(time.Now())
}

// 令牌绑定的用户和客户端信息
type OAuth2Details struct {
	Client *ClientDetails
	User *UserDetails
}

(1)OAuth2Token和OAuth2Details会一一绑定  代表当前操作的用户和客户端

(2)在TokenGrant中 后面主要用TokenService.CreateAccessToken方法来生成访问令牌
(3)TokenService接口来用于生成和管理令牌  用TokenStore保存令牌

type TokenService interface {
    
    TokenService的核心操作
	// 根据访问令牌获取对应的用户信息和客户端信息
	GetOAuth2DetailsByAccessToken(tokenValue string) (*OAuth2Details, error)
	// 根据用户信息和客户端信息 生成访问令牌
	CreateAccessToken(oauth2Details *OAuth2Details) (*OAuth2Token, error)
	// 根据 刷新令牌获取访问令牌
	RefreshAccessToken(refreshTokenValue string) (*OAuth2Token, error)
    
    
    简单的读取操作
	// 根据用户信息和客户端信息获取已生成访问令牌
	GetAccessToken(details *OAuth2Details) (*OAuth2Token, error)
	// 根据访问令牌值获取访问令牌结构体
	ReadAccessToken(tokenValue string) (*OAuth2Token, error)
}
```

核心代码解析

```go
1.CreateAccessToken 生成访问令牌和刷新令牌  
    (1) 通过UUID来生成唯一标识 
    (2)配置访问的有效时间 生成访问令牌和刷新令牌
    (3) JWT格式

2.GetOAuth2DetailByAccessToken 因生成的 访问令牌 和 用户信息与客户端信息一一绑定
	即逆向 观察令牌是否失效 来获取相应信息

3.RefreshAccessToken方法 用于根据刷新令牌来生成新的 访问令牌 和 客户端令牌
```

#### 2.4 TokenStore 令牌存储器

```go
service/token_service.go

使用JWT样式来维护令牌 用户 客户端绑定关系
jwtTokenEnhancer  实现JWTTokenStore的功能
		sign  将令牌对应的用户和客户端写入JWT
		extract 解析JWT
```

#### 2.5 /oauth/token和/oauth/check_token

```go
根据 go-kit库的三层架构来对授权服务器的服务进行实现

token 端点 用于请求访问令牌 根据grantType来识别访问令牌的授权类型，并验证相应的凭证是否有效 来生成令牌

check_token 端点 用于验证访问的令牌的有效性
			 有效 返回令牌绑定的用户信息和客户端信息
1. 初始操作
transport层 /http.go
		验证Authorization请求头中的携带的客户端信息
（1） http层
func makeClientAuthorizationContext(clientDetailsService service.ClientDetailsService, logger log.Logger) kithttp.RequestFunc {

	return func(ctx context.Context, r *http.Request) context.Context {

		if clientId, clientSecret, ok := r.BasicAuth(); ok {
			clientDetails, err := clientDetailsService.GetClientDetailByClientId(ctx, clientId, clientSecret)
			if err == nil {
				return context.WithValue(ctx, endpoint.OAuth2ClientDetailsKey, clientDetails)
			}
		}
		return context.WithValue(ctx, endpoint.OAuth2ErrorKey, ErrInvalidClientRequest)
	}
}

验证有效将客户端信息传递给下游

（2）endpoint层
func MakeClientAuthorizationMiddleware(logger log.Logger) endpoint.Middleware {
	return func(next endpoint.Endpoint) endpoint.Endpoint {

		return func(ctx context.Context, request interface{}) (response interface{}, err error) {

			if err, ok := ctx.Value(OAuth2ErrorKey).(error); ok{
				return nil, err
			}
			if _, ok := ctx.Value(OAuth2ClientDetailsKey).(*model.ClientDetails); !ok{
				return  nil, ErrInvalidClientRequest
			}
			return next(ctx, request)
		}
	}
}

该中间件验证 请求上下文是否携带了客户端信息


endpoint/endpoint.go
2. 定义 token和 check_token 的endpoint层代码
//  make endpoint
1.func MakeTokenEndpoint(svc service.TokenGranter, clientService service.ClientDetailsService) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (response interface{}, err error) {
		req := request.(*TokenRequest)
		token, err := svc.Grant(ctx, req.GrantType, ctx.Value(OAuth2ClientDetailsKey).(*model.ClientDetails), req.Reader)
		var errString = ""
		if err != nil{
			errString = err.Error()
		}

		return TokenResponse{
			AccessToken:token,
			Error:errString,
		}, nil
	}
}


2.func MakeCheckTokenEndpoint(svc service.TokenService) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (response interface{}, err error) {
		req := request.(*CheckTokenRequest)
		tokenDetails, err := svc.GetOAuth2DetailsByAccessToken(req.Token)

		var errString = ""
		if err != nil{
			errString = err.Error()
		}

		return CheckTokenResponse{
			OAuthDetails:tokenDetails,
			Error:errString,
		}, nil
	}
}

```

思路: 

```go
1.MakeTokenEndpoint 端点从context中获取请求客户端信息 
		委托TokenGrant 依据授权类型为客户端生成访问令牌

2.MakeCheckTokenEndpoint 端点将请求中TokenValue传递给下游来验证token的有效性
```

2. transport层端口和请求类型绑定好

#### 2.6 请求访问令牌和刷新令牌

写好main函数 建立service层 endpoint层 transport层 完成oauth服务

```go
consul 服务发现与注册中心绑定
		客户端验证中间件
	  服务监听
	  健康检查Endpoint等等
```



### 3. 资源服务器

持有用户授权的各类资源 

从授权服务器获取到访问令牌的客户端 才能够从资源服务器中请求受保护的资源

#### 3.1 令牌认证

```go
1.从请求中解析出访问令牌, 从Authorization请求中解析出令牌
  然后使用TokenService获取用户信息和客户端信息
 transport/http.go

另外中间件认证 统一验证context中的OAuth2Details是否存在
```

#### 3.2 鉴权

```go
添加MakeAuthorityAuthorizationMiddleware 权限检查中间件
访问的用户具备预设的权限 请求才能进行
```

#### 3.3 访问受限资源

```go
认证中间件 权限检查中间插

1.分/admin 端   和 	/simple端
 需具备Admin权限 	有令牌即可

2.service层 CommonService,go  处理上述凉饿端点
SimpleData  AdminData

3. endpoint层 对应/simple端点 /admin端点建立

4. http.go 将建立好的endpoint通过http的方式暴露出去

5. main.go   对于请求 在请求处理器处添加所需的Context中间件来解析并验证token
			建立service层 endpoint层 transport层
```

### 4.小结




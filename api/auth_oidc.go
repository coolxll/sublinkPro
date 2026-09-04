package api

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/http"
	"strings"
	"sublink/config"
	"sublink/models"
	"sublink/utils"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/gin-gonic/gin"
	"golang.org/x/oauth2"
)

const oidcStateCookieName = "sublink_oidc_state"

func generateRandomState() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// OIDCLogin 发起 OIDC 授权请求
func OIDCLogin(c *gin.Context) {
	oidcCfg := config.GetOIDCConfig()
	if !oidcCfg.Enabled {
		utils.FailWithMsg(c, "OIDC 单点登录未启用")
		return
	}

	if oidcCfg.Issuer == "" || oidcCfg.ClientID == "" || oidcCfg.ClientSecret == "" {
		utils.FailWithMsg(c, "OIDC 配置不完整 (缺少 Issuer / ClientID / ClientSecret)")
		return
	}

	ctx := c.Request.Context()
	provider, err := oidc.NewProvider(ctx, oidcCfg.Issuer)
	if err != nil {
		utils.Error("初始化 OIDC Provider 失败: %v", err)
		utils.FailWithMsg(c, fmt.Sprintf("连接 OIDC 认证中心失败: %v", err))
		return
	}

	state := generateRandomState()
	// 保存 state 到 Cookie，有效期 5 分钟
	c.SetCookie(oidcStateCookieName, state, 300, "/", "", false, true)

	oauth2Config := oauth2.Config{
		ClientID:     oidcCfg.ClientID,
		ClientSecret: oidcCfg.ClientSecret,
		RedirectURL:  oidcCfg.RedirectURI,
		Endpoint:     provider.Endpoint(),
		Scopes:       []string{oidc.ScopeOpenID, "profile", "email"},
	}

	authURL := oauth2Config.AuthCodeURL(state)
	c.Redirect(http.StatusFound, authURL)
}

// OIDCCallback 处理 OIDC 授权回调
func OIDCCallback(c *gin.Context) {
	oidcCfg := config.GetOIDCConfig()
	if !oidcCfg.Enabled {
		utils.FailWithMsg(c, "OIDC 单点登录未启用")
		return
	}

	// 1. 验证 State 防止 CSRF
	savedState, err := c.Cookie(oidcStateCookieName)
	queryState := c.Query("state")
	if err != nil || savedState == "" || savedState != queryState {
		utils.Warn("OIDC 回调 state 校验失败: saved=%s, query=%s", savedState, queryState)
		utils.FailWithMsg(c, "认证请求已过期或 State 无效，请重试")
		return
	}
	// 清除 state Cookie
	c.SetCookie(oidcStateCookieName, "", -1, "/", "", false, true)

	// 2. 检查返回的授权码
	code := c.Query("code")
	if code == "" {
		errMsg := c.Query("error_description")
		if errMsg == "" {
			errMsg = c.Query("error")
		}
		if errMsg == "" {
			errMsg = "认证服务未返回授权码"
		}
		utils.Warn("OIDC 回调缺少授权码: %s", errMsg)
		utils.FailWithMsg(c, errMsg)
		return
	}

	// 3. 用 code 换取 token 并校验 id_token
	ctx := c.Request.Context()
	provider, err := oidc.NewProvider(ctx, oidcCfg.Issuer)
	if err != nil {
		utils.Error("初始化 OIDC Provider 失败: %v", err)
		utils.FailWithMsg(c, "连接 OIDC 认证中心失败")
		return
	}

	oauth2Config := oauth2.Config{
		ClientID:     oidcCfg.ClientID,
		ClientSecret: oidcCfg.ClientSecret,
		RedirectURL:  oidcCfg.RedirectURI,
		Endpoint:     provider.Endpoint(),
		Scopes:       []string{oidc.ScopeOpenID, "profile", "email"},
	}

	oauth2Token, err := oauth2Config.Exchange(ctx, code)
	if err != nil {
		utils.Error("OIDC code 换取令牌失败: %v", err)
		utils.FailWithMsg(c, fmt.Sprintf("获取认证令牌失败: %v", err))
		return
	}

	rawIDToken, ok := oauth2Token.Extra("id_token").(string)
	if !ok {
		utils.Error("OIDC 响应未包含 id_token")
		utils.FailWithMsg(c, "认证响应中缺少 ID 令牌")
		return
	}

	verifier := provider.Verifier(&oidc.Config{ClientID: oidcCfg.ClientID})
	idToken, err := verifier.Verify(ctx, rawIDToken)
	if err != nil {
		utils.Error("验证 ID 令牌失败: %v", err)
		utils.FailWithMsg(c, fmt.Sprintf("ID 令牌验证无效: %v", err))
		return
	}

	var claims struct {
		Email         string `json:"email"`
		EmailVerified bool   `json:"email_verified"`
		Name          string `json:"name"`
		Sub           string `json:"sub"`
		PreferredName string `json:"preferred_username"`
	}
	if err := idToken.Claims(&claims); err != nil {
		utils.Error("解析 ID 令牌声明失败: %v", err)
		utils.FailWithMsg(c, "解析用户信息失败")
		return
	}

	loginEmail := strings.ToLower(strings.TrimSpace(claims.Email))
	if loginEmail == "" && strings.Contains(claims.PreferredName, "@") {
		loginEmail = strings.ToLower(strings.TrimSpace(claims.PreferredName))
	}
	if loginEmail == "" {
		if userInfo, uErr := provider.UserInfo(ctx, oauth2.StaticTokenSource(oauth2Token)); uErr == nil {
			loginEmail = strings.ToLower(strings.TrimSpace(userInfo.Email))
		}
	}
	if loginEmail == "" && claims.Sub != "" {
		loginEmail = claims.Sub
	}
	if loginEmail == "" {
		utils.Warn("OIDC 返回的用户未包含有效身份信息")
		utils.FailWithMsg(c, "OIDC 账号未提供有效用户身份信息")
		return
	}

	// 4. 校验白名单（如果配置了白名单）
	if len(oidcCfg.AllowedEmails) > 0 {
		allowed := false
		for _, email := range oidcCfg.AllowedEmails {
			if strings.EqualFold(loginEmail, email) || email == "*" {
				allowed = true
				break
			}
		}
		if !allowed {
			utils.Warn("OIDC 用户 %s 不在允许登录的白名单内", loginEmail)
			c.Header("Content-Type", "text/html; charset=utf-8")
			c.String(http.StatusForbidden, fmt.Sprintf("<h3>403 访问受限</h3><p>您的邮箱 %s 未在允许登录的管理员白名单列表中。</p>", loginEmail))
			return
		}
	}

	// 5. 映射至本地管理员用户
	targetUser := &models.User{Username: "admin"}
	if err := targetUser.Find(); err != nil {
		// 未找到名为 admin 的用户，查找首个用户
		allUsers, allErr := targetUser.All()
		if allErr != nil || len(allUsers) == 0 {
			utils.Error("未找到本地可绑定的管理员账号")
			utils.FailWithMsg(c, "本地管理员账号不存在，无法完成免密登录")
			return
		}
		*targetUser = allUsers[0]
	}

	// 6. 调用原生 GetToken 签发内部系统 JWT
	token, err := GetToken(targetUser)
	if err != nil {
		utils.Error("签发本地 JWT 失败: %v", err)
		utils.FailWithMsg(c, "生成访问凭据失败")
		return
	}

	// 记录登录通知
	go notifyUserLogin(targetUser.Username, c.ClientIP())

	// 7. 重定向至前端并带上 access_token
	basePath := config.GetWebBasePath()
	if basePath == "" {
		basePath = "/"
	}
	if !strings.HasSuffix(basePath, "/") {
		basePath += "/"
	}

	redirectURL := fmt.Sprintf("%s#access_token=%s", basePath, token)
	c.Redirect(http.StatusTemporaryRedirect, redirectURL)
}

package api

import (
	"encoding/gob"
	"net/http"

	"github.com/HeadStone1/s-ui/database/model"
	"github.com/HeadStone1/s-ui/util/common"

	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
)

const (
	loginUser     = "LOGIN_USER"
	csrfTokenName = "CSRF_TOKEN"
)

func init() {
	gob.Register(model.User{})
}

func SetLoginUser(c *gin.Context, userName string, maxAge int) error {
	options := sessions.Options{
		Path:     "/",
		HttpOnly: true,
		// Keep Secure disabled by default for direct HTTP/IP deployments.
		// Deployments behind HTTPS reverse proxies can enforce HTTPS at the proxy layer.
		Secure:   false,
		SameSite: http.SameSiteLaxMode,
	}
	if maxAge > 0 {
		options.MaxAge = maxAge * 60
	}

	s := sessions.Default(c)
	s.Set(loginUser, userName)
	s.Options(options)

	return s.Save()
}

func SetMaxAge(c *gin.Context) error {
	s := sessions.Default(c)
	s.Options(sessions.Options{
		Path:     "/",
		HttpOnly: true,
		Secure:   false,
		SameSite: http.SameSiteLaxMode,
	})
	return s.Save()
}

func GetLoginUser(c *gin.Context) string {
	s := sessions.Default(c)
	obj := s.Get(loginUser)
	if obj == nil {
		return ""
	}
	objStr, ok := obj.(string)
	if !ok {
		return ""
	}
	return objStr
}

func IsLogin(c *gin.Context) bool {
	return GetLoginUser(c) != ""
}

func EnsureCSRFToken(c *gin.Context) (string, error) {
	s := sessions.Default(c)
	obj := s.Get(csrfTokenName)
	token, ok := obj.(string)
	if ok && token != "" {
		return token, nil
	}
	token = common.Random(32)
	s.Set(csrfTokenName, token)
	return token, s.Save()
}

func SetCSRFHeader(c *gin.Context) error {
	token, err := EnsureCSRFToken(c)
	if err != nil {
		return err
	}
	c.Header("X-CSRF-Token", token)
	return nil
}

func CheckCSRFToken(c *gin.Context) bool {
	s := sessions.Default(c)
	expected, ok := s.Get(csrfTokenName).(string)
	if !ok || expected == "" {
		return false
	}
	actual := c.GetHeader("X-CSRF-Token")
	return actual == expected
}

func ClearSession(c *gin.Context) {
	s := sessions.Default(c)
	s.Clear()
	s.Options(sessions.Options{
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   false,
		SameSite: http.SameSiteLaxMode,
	})
	s.Save()
}

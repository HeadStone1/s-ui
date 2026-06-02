package api

import (
	"encoding/json"
	"time"

	"github.com/HeadStone1/s-ui/logger"
	"github.com/HeadStone1/s-ui/util/common"

	"github.com/gin-gonic/gin"
)

type TokenInMemory struct {
	TokenHash string
	Expiry    int64
	Username  string
	Scope     string
}

type APIv2Handler struct {
	ApiService
	tokens *[]TokenInMemory
}

func NewAPIv2Handler(g *gin.RouterGroup) *APIv2Handler {
	a := &APIv2Handler{}
	a.ReloadTokens()
	a.initRouter(g)
	return a
}

func (a *APIv2Handler) initRouter(g *gin.RouterGroup) {
	g.Use(func(c *gin.Context) {
		a.checkToken(c)
	})
	g.POST("/:postAction", a.postHandler)
	g.GET("/:getAction", a.getHandler)
}

func (a *APIv2Handler) postHandler(c *gin.Context) {
	token := a.findToken(c)
	username := token.Username
	action := c.Param("postAction")

	switch action {
	case "save":
		if !tokenAllows(token.Scope, "write") {
			jsonMsg(c, "failed", common.NewError("write scope required"))
			return
		}
		a.ApiService.Save(c, username)
	case "restartApp":
		if !tokenAllows(token.Scope, "admin") {
			jsonMsg(c, "failed", common.NewError("admin scope required"))
			return
		}
		a.ApiService.RestartApp(c)
	case "restartSb":
		if !tokenAllows(token.Scope, "admin") {
			jsonMsg(c, "failed", common.NewError("admin scope required"))
			return
		}
		a.ApiService.RestartSb(c)
	case "linkConvert":
		if !tokenAllows(token.Scope, "write") {
			jsonMsg(c, "failed", common.NewError("write scope required"))
			return
		}
		a.ApiService.LinkConvert(c)
	case "subConvert":
		if !tokenAllows(token.Scope, "write") {
			jsonMsg(c, "failed", common.NewError("write scope required"))
			return
		}
		a.ApiService.SubConvert(c)
	case "importdb":
		if !tokenAllows(token.Scope, "admin") {
			jsonMsg(c, "failed", common.NewError("admin scope required"))
			return
		}
		a.ApiService.ImportDb(c)
	default:
		jsonMsg(c, "failed", common.NewError("unknown action: ", action))
	}
}

func (a *APIv2Handler) getHandler(c *gin.Context) {
	action := c.Param("getAction")

	switch action {
	case "load":
		a.ApiService.LoadData(c)
	case "inbounds", "outbounds", "endpoints", "services", "tls", "clients", "config":
		err := a.ApiService.LoadPartialData(c, []string{action})
		if err != nil {
			jsonMsg(c, action, err)
		}
		return
	case "users":
		a.ApiService.GetUsers(c)
	case "settings":
		a.ApiService.GetSettings(c)
	case "stats":
		a.ApiService.GetStats(c)
	case "status":
		a.ApiService.GetStatus(c)
	case "onlines":
		a.ApiService.GetOnlines(c)
	case "logs":
		a.ApiService.GetLogs(c)
	case "changes":
		a.ApiService.CheckChanges(c)
	case "keypairs":
		a.ApiService.GetKeypairs(c)
	case "getdb":
		token := a.findToken(c)
		if !tokenAllows(token.Scope, "admin") {
			jsonMsg(c, "failed", common.NewError("admin scope required"))
			return
		}
		a.ApiService.GetDb(c)
	case "checkOutbound":
		a.ApiService.GetCheckOutbound(c)
	default:
		jsonMsg(c, "failed", common.NewError("unknown action: ", action))
	}
}

func (a *APIv2Handler) findUsername(c *gin.Context) string {
	return a.findToken(c).Username
}

func (a *APIv2Handler) findToken(c *gin.Context) TokenInMemory {
	token := c.Request.Header.Get("Token")
	for index, t := range *a.tokens {
		if t.Expiry > 0 && t.Expiry < time.Now().Unix() {
			(*a.tokens) = append((*a.tokens)[:index], (*a.tokens)[index+1:]...)
			continue
		}
		if common.CheckTokenHash(token, t.TokenHash) {
			return t
		}
	}
	return TokenInMemory{}
}

func (a *APIv2Handler) checkToken(c *gin.Context) {
	username := a.findUsername(c)
	if username != "" {
		c.Next()
		return
	}
	jsonMsg(c, "", common.NewError("invalid token"))
	c.Abort()
}

func tokenAllows(scope string, required string) bool {
	if scope == "admin" {
		return true
	}
	if scope == "write" {
		return required == "read" || required == "write"
	}
	return required == "read"
}

func (a *APIv2Handler) ReloadTokens() {
	tokens, err := a.ApiService.LoadTokens()
	if err == nil {
		var newTokens []TokenInMemory
		err = json.Unmarshal(tokens, &newTokens)
		if err != nil {
			logger.Error("unable to load tokens: ", err)
		}
		a.tokens = &newTokens
	} else {
		logger.Error("unable to load tokens: ", err)
	}
}

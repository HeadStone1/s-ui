package sub

import (
	"github.com/HeadStone1/s-ui/database/model"
	"github.com/HeadStone1/s-ui/logger"
	"github.com/HeadStone1/s-ui/service"

	"github.com/gin-gonic/gin"
)

type SubHandler struct {
	service.SettingService
	SubService
	JsonService
	ClashService
}

func NewSubHandler(g *gin.RouterGroup) {
	a := &SubHandler{}
	a.initRouter(g)
}

func (s *SubHandler) initRouter(g *gin.RouterGroup) {
	// Keep only the hardened two-segment subscription route.
	// Gin does not allow multiple wildcard names at the same path level,
	// so the old name-only route must not be registered alongside this one.
	g.GET("/:clientId/:secret", s.subsWithSecret)
	g.HEAD("/:clientId/:secret", s.subHeadersWithSecret)
}

func (s *SubHandler) subsWithSecret(c *gin.Context) {
	client, err := s.SubService.getClientBySecret(c.Param("clientId"), c.Param("secret"))
	if err != nil {
		logger.Error(err)
		c.String(400, "Error!")
		return
	}
	s.writeSubResponse(c, client)
}

func (s *SubHandler) writeSubResponse(c *gin.Context, client *model.Client) {
	var headers []string
	var result *string
	var err error
	format, isFormat := c.GetQuery("format")
	if isFormat {
		switch format {
		case "json":
			result, headers, err = s.JsonService.GetJsonForClient(client, format)
		case "clash":
			result, headers, err = s.ClashService.GetClashForClient(client)
		}
		if err != nil || result == nil {
			logger.Error(err)
			c.String(400, "Error!")
			return
		}
	} else {
		result, headers, err = s.SubService.GetSubsForClient(client)
		if err != nil || result == nil {
			logger.Error(err)
			c.String(400, "Error!")
			return
		}
	}
	s.addHeaders(c, headers)
	c.String(200, *result)
}

func (s *SubHandler) subHeadersWithSecret(c *gin.Context) {
	client, err := s.SubService.getClientBySecret(c.Param("clientId"), c.Param("secret"))
	if err != nil {
		logger.Error(err)
		c.String(400, "Error!")
		return
	}

	headers := s.SubService.getClientHeaders(client)
	s.addHeaders(c, headers)

	c.Status(200)
}

func (s *SubHandler) addHeaders(c *gin.Context, headers []string) {
	c.Writer.Header().Set("Subscription-Userinfo", headers[0])
	c.Writer.Header().Set("Profile-Update-Interval", headers[1])
	c.Writer.Header().Set("Profile-Title", headers[2])
}

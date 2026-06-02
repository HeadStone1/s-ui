package util

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/HeadStone1/s-ui/logger"
	"github.com/HeadStone1/s-ui/util/common"
)

func GetExternalLink(url string) string {
	if err := validateExternalURL(url); err != nil {
		logger.Warning("sub: blocked external URL:", err)
		return ""
	}
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		DialContext: func(ctx context.Context, network string, addr string) (net.Conn, error) {
			host, _, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}
			if err := validateExternalHost(host); err != nil {
				return nil, err
			}
			dialer := &net.Dialer{Timeout: 5 * time.Second}
			return dialer.DialContext(ctx, network, addr)
		},
	}

	client := &http.Client{
		Transport: tr,
		Timeout:   5 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return validateExternalURL(req.URL.String())
		},
	}

	request, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		logger.Warning("sub: Error creating HTTP request:", err)
		return ""
	}
	response, err := client.Do(request)
	if err != nil {
		logger.Warning("sub: Error making HTTP request:", err)
		return ""
	}
	defer response.Body.Close()

	body, err := io.ReadAll(io.LimitReader(response.Body, 5<<20))
	if err != nil {
		logger.Warning("sub: Error reading response body:", err)
		return ""
	}

	data := StrOrBase64Encoded(string(body))
	return data
}

func validateExternalURL(rawURL string) error {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return err
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return common.NewError("unsupported URL scheme")
	}
	return validateExternalHost(parsed.Hostname())
}

func validateExternalHost(host string) error {
	if host == "" {
		return common.NewError("missing host")
	}
	ip := net.ParseIP(host)
	if ip != nil {
		if isBlockedExternalIP(ip) {
			return common.NewError("blocked private or local address")
		}
		return nil
	}
	ips, err := net.LookupIP(host)
	if err != nil {
		return err
	}
	for _, resolvedIP := range ips {
		if isBlockedExternalIP(resolvedIP) {
			return common.NewError("blocked private or local address")
		}
	}
	return nil
}

func isBlockedExternalIP(ip net.IP) bool {
	return ip.IsLoopback() ||
		ip.IsPrivate() ||
		ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() ||
		ip.IsUnspecified()
}

func GetExternalSub(url string) ([]map[string]interface{}, error) {
	var err error
	var result []map[string]interface{}

	if len(url) == 0 {
		return nil, common.NewError("no url")
	}

	data := GetExternalLink(url)
	if len(data) == 0 {
		return nil, common.NewError("no result")
	}

	// if the data is a JSON object
	if strings.HasPrefix(data, "{") && strings.HasSuffix(data, "}") {
		var jsonData map[string]interface{}
		err = json.Unmarshal([]byte(data), &jsonData)
		if err != nil {
			logger.Warning("sub: Error unmarshalling JSON:", err)
			return nil, err
		}
		outbounds, ok := jsonData["outbounds"].([]any)
		if !ok {
			logger.Warning("sub: Error getting outbounds:", err)
			return nil, err
		}
		for _, outbound := range outbounds {
			outboundMap, ok := outbound.(map[string]interface{})
			if ok && len(outboundMap) > 0 {
				oType, _ := outboundMap["type"].(string)
				switch oType {
				case "urltest":
				case "direct":
				case "selector":
				case "block":
					continue
				default:
					result = append(result, outboundMap)
				}
			}
		}
		if len(result) == 0 {
			return nil, common.NewError("no result")
		}
		return result, nil
	} else {
		// if data is a text
		links := strings.Split(data, "\n")
		for _, link := range links {
			linkToJson, _, err := GetOutbound(link, 0)
			if err == nil {
				result = append(result, *linkToJson)
			}
		}
	}
	if len(result) == 0 {
		return nil, common.NewError("no result")
	}
	return result, nil
}

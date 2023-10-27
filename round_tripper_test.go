package cloudflarebp_test

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"testing"

	_ "github.com/joho/godotenv/autoload"

	browser "github.com/EDDYCJY/fake-useragent"
	cloudflarebp "github.com/m41k1n4177/cloudflare-bp-go"
	"github.com/stretchr/testify/assert"
	"golang.org/x/net/proxy"
)

func TestApplyBypass(t *testing.T) {
	client := &http.Client{}

	t.Run("default client", func(t *testing.T) {
		res, err := client.Get("https://www.patreon.com/login")
		assert.NoError(t, err)
		assert.Equal(t, 403, res.StatusCode)
	})

	client.Transport = &http.Transport{TLSClientConfig: &tls.Config{CurvePreferences: []tls.CurveID{tls.CurveP256, tls.CurveP384, tls.CurveP521, tls.X25519}}}

	t.Run("modified client", func(t *testing.T) {
		req, err := http.NewRequest(http.MethodGet, "https://www.patreon.com/login", nil)
		assert.NoError(t, err)

		hdrs := map[string]string{
			"Accept":          "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8",
			"Accept-Language": "en-US,en;q=0.5",
			"User-Agent":      browser.Firefox(),
		}

		for header, value := range hdrs {
			if _, ok := req.Header[header]; !ok {
				req.Header.Set(header, value)
			}
		}

		res, err := client.Do(req)
		assert.NoError(t, err)
		defer res.Body.Close()

		assert.Equal(t, 200, res.StatusCode)
	})
}

func TestApplyCloudFlareByPassDefaultClient(t *testing.T) {
	client := http.DefaultClient

	res, err := client.Get("https://www.patreon.com/login")
	assert.NoError(t, err)
	assert.Equal(t, 403, res.StatusCode)

	// apply our bypass for request headers and client TLS configurations
	client.Transport = cloudflarebp.AddByPass(http.DefaultClient.Transport)
	res, err = client.Get("https://www.patreon.com/login")
	assert.NoError(t, err)
	assert.Equal(t, 200, res.StatusCode)
}

func TestApplyCloudFlareByPassDefinedTransport(t *testing.T) {
	client := &http.Client{
		Transport: &http.Transport{},
	}

	// if the client requests something before applying the fix some configurations are applied already
	// and our ByPass won't work anymore, so we have to apply our ByPass as the first thing
	client.Transport = cloudflarebp.AddByPass(client.Transport)

	res, err := client.Get("https://www.patreon.com/login")
	assert.NoError(t, err)
	assert.Equal(t, 200, res.StatusCode)
}

// TestAddByPassSocksProxy tests the CloudFlare bypass while we're using a SOCK5 proxy transport layer.
func TestAddByPassSocksProxy(t *testing.T) {

	auth := proxy.Auth{
		User:     os.Getenv("PROXY_USER"),
		Password: os.Getenv("PROXY_PASS"),
	}
	dialer, err := proxy.SOCKS5(
		"tcp",
		fmt.Sprintf("%s:%s", os.Getenv("PROXY_HOST"), os.Getenv("PROXY_PORT_SOCKS5")),
		&auth,
		proxy.Direct,
	)
	assert.NoError(t, err)

	dc := dialer.(interface {
		DialContext(ctx context.Context, network, addr string) (net.Conn, error)
	})

	client := &http.Client{
		Transport: &http.Transport{DialContext: dc.DialContext},
	}

	// if the client requests something before applying the fix some configurations are applied already
	// and our ByPass won't work anymore, so we have to apply our ByPass as the first thing
	client.Transport = cloudflarebp.AddByPass(client.Transport)

	res, err := client.Get("https://www.patreon.com/login")
	assert.NoError(t, err)
	assert.Equal(t, 200, res.StatusCode)
}

// TestAddByPassHTTPProxy tests the CloudFlare bypass while we're using a HTTP proxy transport layer.
func TestAddByPassHTTPProxy(t *testing.T) {
	proxyURL, _ := url.Parse(
		fmt.Sprintf(
			"http://%s:%s@%s:%s",
			url.QueryEscape(os.Getenv("PROXY_USER")), url.QueryEscape(os.Getenv("PROXY_PASS")),
			url.QueryEscape(os.Getenv("PROXY_HOST")), url.QueryEscape(os.Getenv("PROXY_PORT_HTTP")),
		),
	)

	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
			TLSClientConfig: &tls.Config{
				CurvePreferences: []tls.CurveID{tls.X25519, tls.CurveP256, tls.CurveP384},
			},
		},
	}

	res, err := client.Get("https://www.patreon.com/login")
	assert.NoError(t, err)
	assert.Equal(t, 403, res.StatusCode)

	// if the client requests something before applying the fix some configurations are applied already
	// and our ByPass won't work anymore, so we have to apply our ByPass as the first thing
	client.Transport = cloudflarebp.AddByPass(client.Transport)

	res, err = client.Get("https://www.patreon.com/login")
	assert.NoError(t, err)
	assert.Equal(t, 200, res.StatusCode)
}

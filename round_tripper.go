package cloudflarebp

import (
	"crypto/tls"
	"net/http"

	browser "github.com/EDDYCJY/fake-useragent"
)

type (
	cloudFlareRoundTripper struct {
		inner   http.RoundTripper
		options Options
	}

	Options struct {
		AddMissingHeaders bool
		Headers           map[string]string
	}
)

func AddByPass(roundTripper http.RoundTripper, options ...Options) http.RoundTripper {
	switch tr := roundTripper.(type) {
	case *http.Transport:
		tr.TLSClientConfig = getCloudFlareTLSConfiguration()
	default:
		tr = &http.Transport{
			TLSClientConfig: getCloudFlareTLSConfiguration(),
		}
		roundTripper = tr
	}

	return &cloudFlareRoundTripper{
		inner: roundTripper,
		options: func() Options {
			if len(options) > 0 {
				return options[0]
			}
			return getDefaultOptions()
		}(),
	}
}

func (ug *cloudFlareRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) {
	if !ug.options.AddMissingHeaders {
		return ug.inner.RoundTrip(r)
	}

	for header, value := range ug.options.Headers {
		if _, ok := r.Header[header]; !ok {
			r.Header.Set(header, value)
		}
	}

	return ug.inner.RoundTrip(r)
}

func getCloudFlareTLSConfiguration() *tls.Config {
	return &tls.Config{
		CurvePreferences: []tls.CurveID{tls.X25519, tls.CurveP256},
	}
}

func getDefaultOptions() Options {
	return Options{
		AddMissingHeaders: true,
		Headers: map[string]string{
			"Accept":          "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8",
			"Accept-Language": "en-US,en;q=0.5",
			"User-Agent":      browser.Firefox(),
		},
	}
}

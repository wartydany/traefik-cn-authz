package traefik_cn_authz

import (
	"context"
	"fmt"
	"net/http"
	"regexp"
)

type Config struct {
	Regex string
}

func CreateConfig() *Config {
	return &Config{
		Regex: "",
	}
}

type CertAuthz struct {
	next     http.Handler
	regex    *regexp.Regexp
	name     string
}

func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	if config.Regex == "" {
		return nil, fmt.Errorf("regex must be provided")
	}

	var to_compile = config.Regex

	var compiled, err = regexp.Compile(to_compile)
	if err != nil {
		return nil, err
	}

	return &CertAuthz{
		regex:    compiled,
		next:     next,
		name:     name,
	}, nil
}

func (a *CertAuthz) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	if req.TLS != nil && len(req.TLS.PeerCertificates) != 0 {
		var cert = req.TLS.PeerCertificates[0] // leaf certificate
		var cn = cert.Subject.CommonName
        if a.regex.MatchString(cn) {
            a.next.ServeHTTP(rw, req)
            return
        }
	}
	http.Error(rw, "client certificate CN does not match", http.StatusForbidden)
}

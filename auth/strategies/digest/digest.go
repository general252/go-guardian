// Package digest provides authentication strategy,
// to authenticate HTTP requests using the standard digest scheme as described in RFC 7616.
package digest

import (
	"context"
	"crypto"
	"crypto/md5"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"net/http"
	"strings"

	"github.com/shaj13/go-guardian/v2/auth"
)

// ErrInvalidResponse is returned by Strategy when client authz response does not match server hash.
var ErrInvalidResponse = errors.New("strategies/digest: Invalid Response")

// FetchUser a callback function to return the user password and user info.
type FetchUser func(userName string) (string, auth.Info, error)

// Digest authentication strategy.
type Digest struct {
	fn    FetchUser
	chash crypto.Hash
	c     auth.Cache
	h     Header
}

func (d *Digest) getResponse(h Header, passwd string, method string, url string, entityBody []byte) string {
	var (
		A1 string
		A2 string
		HD string
	)

	if h.Algorithm() == "md5" {
		A1 = h.UserName() + ":" + h.Realm() + ":" + passwd

	} else if h.Algorithm() == "md5-sess" {
		A1 = h.UserName() + ":" + h.Realm() + ":" + passwd + ":" + h.Nonce() + ":" + h.Cnonce()
	}

	if strings.Contains(h.QOP(), "auth-int") {
		A2 = method + ":" + url + d.md5Hash(entityBody)
		HD = h.Nonce() + ":" + h.NC() + ":" + h.Cnonce() + ":" + h.QOP()
	} else {
		A2 = method + ":" + url
		HD = h.Nonce()
	}

	HA1 := d.hash(A1)
	HA2 := d.hash(A2)

	response := d.hash(HA1 + ":" + HD + ":" + HA2)
	return response
}

// Authenticate user request and returns user info, Otherwise error.
func (d *Digest) Authenticate(ctx context.Context, r *http.Request) (auth.Info, error) {
	var (
		authz  = r.Header.Get("Authorization")
		method = r.Method
		url    = r.RequestURI
	)
	h := make(Header)

	if err := h.Parse(authz); err != nil {
		return nil, err
	}

	passwd, info, err := d.fn(h.UserName())
	if err != nil {
		return nil, err
	}

	HKD := d.getResponse(h, passwd, method, url, nil)
	if subtle.ConstantTimeCompare([]byte(HKD), []byte(h.Response())) != 1 {
		return nil, ErrInvalidResponse
	}

	if _, ok := d.c.Load(h.Nonce()); !ok {
		return nil, ErrInvalidResponse
	}

	// validate the header values.
	ch := d.h.Clone()
	ch.SetNonce(h.Nonce())

	if err := ch.Compare(h); err != nil {
		return nil, err
	}

	return info, nil
}

// GetChallenge returns string indicates the authentication scheme.
// Typically used to adds a HTTP WWW-Authenticate header.
func (d *Digest) GetChallenge() string {
	h := d.h.Clone()
	str := h.WWWAuthenticate()
	d.c.Store(h.Nonce(), struct{}{})
	return str
}

// AuthenticateClient 构建客户端请求Authenticate值
func (d *Digest) AuthenticateClient(r *http.Response, fn func(h Header), passwd string, entityBody []byte) (string, error) {
	// 参考 https://www.jianshu.com/p/18fb07f2f65e
	var (
		WWWAuthenticate = r.Header.Get("WWW-Authenticate")
		method          = r.Request.Method
		url             = r.Request.URL.Path
	)
	h := make(Header)

	if err := h.Parse(WWWAuthenticate); err != nil {
		return "", err
	}

	if fn != nil {
		fn(h)
	}

	if len(h.URI()) == 0 {
		h.SetURI(url)
	}

	if len(h.NC()) == 0 {
		h.SetNC("00000001")
	}

	if len(h.Cnonce()) == 0 {
		h.SetCnonce(SecretKey())
	}

	h.SetResponse(d.getResponse(h, passwd, method, h.URI(), entityBody))

	return h.Authenticate(), nil
}

func (d *Digest) hash(str string) string {
	h := d.chash.New()
	_, _ = h.Write([]byte(str))
	p := h.Sum(nil)
	return hex.EncodeToString(p)
}

func (d *Digest) md5Hash(data []byte) string {
	h := md5.New()
	_, _ = h.Write(data)
	p := h.Sum(nil)
	return hex.EncodeToString(p)
}

// New returns digest authentication strategy.
// Digest strategy use MD5 as default hash.
// Digest use cache to store nonce.
func New(f FetchUser, c auth.Cache, opts ...auth.Option) *Digest {
	d := new(Digest)
	d.fn = f
	d.chash = crypto.MD5
	d.c = c
	d.h = make(Header)
	d.h.SetRealm("Users")
	d.h.SetAlgorithm("md5")
	d.h.SetOpaque(SecretKey())

	for _, opt := range opts {
		opt.Apply(d)
	}

	return d
}

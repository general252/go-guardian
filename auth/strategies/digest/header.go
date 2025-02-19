package digest

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

// ErrInavlidHeader is returned by Header parse when  authz header is not digest.
var ErrInavlidHeader = errors.New("strategies/digest: Invalid Authorization Header")

const (
	username  = "username"  // username: 用户名（网站定义）
	realm     = "realm"     // password: 密码
	uri       = "uri"       // uri: 请求的uri(只是path)
	algorithm = "algorithm" // 默认是md5加密
	nonce     = "nonce"     // nonce: 服务器发给客户端的随机的字符串
	cnonce    = "cnonce"    // cnonce(clinetNonce): 客户端发送给服务器的随机字符串
	nc        = "nc"        // nc(nonceCount):请求的次数，用于标记，计数，防止重放攻击
	qop       = "qop"       // qop: 保护质量参数,一般是auth,或auth-int,这会影响摘要的算法
	response  = "response"  // 客户端根据算法算出的摘要值, 服务器端用此验证客户端
	opaque    = "opaque"    // 透传, 客户端原样返回
)

// Header represents The Authorization Header Field,
// and WWW-Authenticate Response Header Field as described in RFC 7616
type Header map[string]string

// UserName return the The user's name in the specified realm.
func (h Header) UserName() string {
	return h[username]
}

// SetUserName sets user name.
func (h Header) SetUserName(u string) {
	h[username] = u
}

// Realm return a string to be displayed to users so they know which username and
// password to use.
// See https://tools.ietf.org/html/rfc7616#section-3.3
func (h Header) Realm() string {
	return h[realm]
}

// SetRealm sets the realm.
func (h Header) SetRealm(r string) {
	h[realm] = r
}

// URI return Effective Request URI
// See https://tools.ietf.org/html/rfc7230#section-5.5
func (h Header) URI() string {
	return h[uri]
}

// SetURI sets Effective Request URI.
func (h Header) SetURI(u string) {
	h[uri] = u
}

// Algorithm return a string indicating an hash algorithm used to produce the digest and an
// unkeyed digest.
func (h Header) Algorithm() string {
	return h[algorithm]
}

// SetAlgorithm sets hash algorithm.
func (h Header) SetAlgorithm(a string) {
	h[algorithm] = a
}

// Nonce A string of hex represents uniquely generated key of 16 byte.
func (h Header) Nonce() string {
	return h[nonce]
}

// SetNonce sets the nounce.
func (h Header) SetNonce(n string) {
	h[nonce] = n
}

// Cnonce returns string of client nounce.
func (h Header) Cnonce() string {
	return h[cnonce]
}

// SetCnonce sets the client nounce.
func (h Header) SetCnonce(cn string) {
	h[cnonce] = cn
}

// NC returns nonce count.
func (h Header) NC() string {
	return h[nc]
}

// SetNC set nonce count.
func (h Header) SetNC(n string) {
	h[nc] = n
}

// QOP returns quality of protection e.g auth.
func (h Header) QOP() string {
	return h[qop]
}

// SetQOP sets the QOP.
func (h Header) SetQOP(q string) {
	h[qop] = q
}

// Response returns A string of the hex digits computed by client.
func (h Header) Response() string {
	return h[response]
}

// SetResponse sets the client response.
func (h Header) SetResponse(r string) {
	h[response] = r
}

// Opaque A string of hex represents uniquely generated key of 16 byte.
func (h Header) Opaque() string {
	return h[opaque]
}

// SetOpaque sets the opaque.
func (h Header) SetOpaque(o string) {
	h[opaque] = o
}

// Parse The Authorization Header string.
func (h Header) Parse(authorization string) error {
	s := strings.SplitN(authorization, " ", 2)
	if len(s) != 2 || s[0] != "Digest" {
		return ErrInavlidHeader
	}

	list := strings.Split(s[1], ",")

	for _, v := range list {
		v = strings.ReplaceAll(v, `"`, "")
		kv := strings.SplitN(v, "=", 2)
		key := strings.TrimSpace(kv[0])
		value := strings.TrimSpace(kv[1])
		h[key] = value
	}

	return nil
}

// WWWAuthenticate return string represents HTTP WWW-Authenticate header field with Digest scheme.
func (h Header) WWWAuthenticate() string {
	if len(h.Nonce()) == 0 {
		h.SetNonce(SecretKey())
	}

	if len(h.Opaque()) == 0 {
		h.SetOpaque(SecretKey())
	}

	h.SetQOP("auth")

	s := fmt.Sprintf(
		`Digest realm="%s", nonce="%s", opaque="%s", algorithm=%s, qop="%s"`,
		h.Realm(),
		h.Nonce(),
		h.Opaque(),
		h.Algorithm(),
		h.QOP(),
	)

	return s
}

func (h Header) Authenticate() string {

	s := fmt.Sprintf(`Digest username="%s",realm="%s",nonce="%s",uri="%s",algorithm=%s,qop="%s",nc="%s",cnonce="%s",response="%s",opaque="%s"`,
		h.UserName(),
		h.Realm(),
		h.Nonce(),
		h.URI(),
		h.Algorithm(),
		h.QOP(),
		h.NC(),
		h.Cnonce(),
		h.Response(),
		h.Opaque(),
	)

	return s
}

// Compare server header vs client header returns error if any diff found.
func (h Header) Compare(ch Header) error {
	for k, v := range h {
		cv := ch[k]
		if !strings.EqualFold(cv, v) {
			return fmt.Errorf("strategies/digest: %s Does not match value in provided header", k)
		}
	}
	return nil
}

// String describe header as a string
func (h Header) String() string {
	str := "Digest "

	for k, v := range h {
		str = str + k + "=" + v + ", "
	}

	return str[:len(str)-2]
}

// Clone returns a copy of h or nil if h is nil.
func (h Header) Clone() Header {
	if h == nil {
		return nil
	}
	h2 := make(Header, len(h))
	for k, v := range h {
		h2[k] = v
	}

	return h2
}

func SecretKey() string {
	secret := make([]byte, 16)
	_, err := rand.Read(secret)
	if err != nil {
		panic(err)
	}
	return hex.EncodeToString(secret)
}

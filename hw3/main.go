package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const tokenTTL = time.Hour

var errNoToken = errors.New("missing token")

type config struct {
	addr     string
	upstream string
	secret   string
	user     string
	pass     string
}

type gate struct {
	cfg   config
	proxy *httputil.ReverseProxy
}

func main() {
	cfg, err := loadConfig()
	if err != nil {
		log.Fatal(err)
	}
	upstream, err := url.Parse(cfg.upstream)
	if err != nil || upstream.Scheme == "" || upstream.Host == "" {
		log.Fatal("UPSTREAM must be an absolute URL, like http://httpbin:8081")
	}

	proxy := httputil.NewSingleHostReverseProxy(upstream)
	proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		log.Printf("upstream: %v", err)
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": "upstream unavailable"})
	}

	log.Printf("listening on %s, forwarding to %s", cfg.addr, cfg.upstream)
	log.Fatal(http.ListenAndServe(cfg.addr, &gate{cfg: cfg, proxy: proxy}))
}

func loadConfig() (config, error) {
	cfg := config{
		addr:     getenv("ADDR", ":80"),
		upstream: getenv("UPSTREAM", "http://127.0.0.1:8081"),
		secret:   os.Getenv("JWT_SECRET"),
		user:     os.Getenv("AUTH_USER"),
		pass:     os.Getenv("AUTH_PASS"),
	}
	if len(cfg.secret) < 32 {
		return config{}, fmt.Errorf("JWT_SECRET must be at least 32 characters")
	}
	if cfg.user == "" || cfg.pass == "" {
		return config{}, fmt.Errorf("AUTH_USER and AUTH_PASS are required")
	}
	return cfg, nil
}

func (g *gate) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// این مسیر مال خود پروکسی است. رمز این‌جا می‌ماند و به سرویس قدیمی نمی‌رود.
	if r.URL.Path == "/auth/login" {
		if r.Method != http.MethodPost {
			writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "use POST"})
			return
		}
		g.login(w, r)
		return
	}

	user, err := g.authorize(r)
	if err != nil {
		msg := "invalid token"
		if errors.Is(err, errNoToken) {
			msg = "missing token"
		} else if errors.Is(err, jwt.ErrTokenExpired) {
			msg = "token expired"
		}
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": msg})
		return
	}

	// توکن را جلو نمی‌فرستیم. اسم کاربر را از روی امضا خودمان می‌نویسیم،
	// نه از هدری که کلاینت ممکن است جعل کرده باشد.
	r.Header.Del("Authorization")
	r.Header.Set("X-Forwarded-User", user)
	g.proxy.ServeHTTP(w, r)
}

func (g *gate) login(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad request"})
		return
	}
	if body.Username != g.cfg.user || body.Password != g.cfg.pass {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}

	token, err := g.sign(body.Username, time.Now())
	if err != nil {
		log.Printf("sign: %v", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not sign token"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"token":      token,
		"expires_in": int(tokenTTL.Seconds()),
	})
}

func (g *gate) authorize(r *http.Request) (string, error) {
	raw, ok := bearerToken(r.Header.Get("Authorization"))
	if !ok {
		return "", errNoToken
	}
	return g.parse(raw)
}

func bearerToken(header string) (string, bool) {
	scheme, token, ok := strings.Cut(header, " ")
	if !ok || !strings.EqualFold(scheme, "Bearer") {
		return "", false
	}
	token = strings.TrimSpace(token)
	if token == "" {
		return "", false
	}
	return token, true
}

func (g *gate) sign(user string, now time.Time) (string, error) {
	claims := jwt.RegisteredClaims{
		Subject:   user,
		IssuedAt:  jwt.NewNumericDate(now),
		ExpiresAt: jwt.NewNumericDate(now.Add(tokenTTL)),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(g.cfg.secret))
}

func (g *gate) parse(raw string) (string, error) {
	claims := &jwt.RegisteredClaims{}
	parsed, err := jwt.ParseWithClaims(raw, claims, func(t *jwt.Token) (any, error) {
		// alg=none یا RS256 این‌جا رد می‌شود. فقط HMAC، یعنی HS256، قبول است.
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method %v", t.Header["alg"])
		}
		return []byte(g.cfg.secret), nil
	}, jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()}))
	if err != nil {
		return "", err
	}
	if !parsed.Valid || claims.Subject == "" {
		return "", fmt.Errorf("invalid token")
	}
	return claims.Subject, nil
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func getenv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

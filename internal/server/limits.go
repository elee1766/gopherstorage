package server

import (
	"context"
	"math"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	defaultMaxConcurrentRequests = 128
	defaultRatePerMinute         = 600
	defaultRateBurst             = 120
	defaultMaxRateClients        = 10000
	defaultRequestTimeout        = 5 * time.Minute
	rateClientExpiry             = 10 * time.Minute
	maxConcurrentRequests        = 4096
	maxRatePerMinute             = 100_000
	maxRateBurst                 = 10_000
	maxRateClients               = 100_000
)

type clientRate struct {
	tokens   float64
	lastSeen time.Time
	updated  time.Time
}

// requestLimits bounds active requests and the memory used by per-client rate
// state. Forwarded IP headers are intentionally ignored.
type requestLimits struct {
	active         chan struct{}
	mu             sync.Mutex
	clients        map[string]clientRate
	perMinute      int
	burst          int
	maxClients     int
	requestTimeout time.Duration
	clientExpiry   time.Duration
	nextCleanup    time.Time
	now            func() time.Time
}

func newRequestLimits(maxConcurrent, perMinute, burst, maxClients int, requestTimeout time.Duration) *requestLimits {
	if maxConcurrent <= 0 {
		maxConcurrent = defaultMaxConcurrentRequests
	}
	if perMinute <= 0 {
		perMinute = defaultRatePerMinute
	}
	if burst <= 0 {
		burst = defaultRateBurst
	}
	if maxClients <= 0 {
		maxClients = defaultMaxRateClients
	}
	if requestTimeout <= 0 {
		requestTimeout = defaultRequestTimeout
	}
	maxConcurrent = min(maxConcurrent, maxConcurrentRequests)
	perMinute = min(perMinute, maxRatePerMinute)
	burst = min(burst, maxRateBurst)
	maxClients = min(maxClients, maxRateClients)
	requestTimeout = min(requestTimeout, defaultRequestTimeout)
	return &requestLimits{
		active:         make(chan struct{}, maxConcurrent),
		clients:        make(map[string]clientRate),
		perMinute:      perMinute,
		burst:          burst,
		maxClients:     maxClients,
		requestTimeout: requestTimeout,
		clientExpiry:   rateClientExpiry,
		now:            time.Now,
	}
}

func (l *requestLimits) middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := remoteIP(r.RemoteAddr)
		retryAfter, ok := l.allow(ip)
		if !ok {
			w.Header().Set("Retry-After", strconvSeconds(retryAfter))
			http.Error(w, "too many requests", http.StatusTooManyRequests)
			return
		}
		select {
		case l.active <- struct{}{}:
			defer func() { <-l.active }()
		default:
			w.Header().Set("Retry-After", "1")
			http.Error(w, "server busy", http.StatusTooManyRequests)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), l.requestTimeout)
		defer cancel()
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func (s *Server) requestBoundary(next http.Handler) http.Handler {
	httpCfg := s.cfg.HTTP
	limits := newRequestLimits(
		httpCfg.MaxConcurrentRequests,
		httpCfg.RatePerMinute,
		httpCfg.RateBurst,
		httpCfg.MaxRateClients,
		httpCfg.RequestTimeout,
	)
	limited := limits.middleware(next)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Cache-Control", "no-store")
		if r.URL.Path == "/auth/callback" {
			h.Set("Referrer-Policy", "no-referrer")
		} else {
			h.Set("Referrer-Policy", "same-origin")
		}
		if s.httpsConfiguredHost(r.Host) {
			h.Set("Strict-Transport-Security", "max-age=31536000")
		}
		if r.Host == "" {
			http.Error(w, "invalid host", http.StatusBadRequest)
			return
		}
		if !strings.EqualFold(r.Host, s.cfg.Host()) &&
			(s.cfg.ViewHost() == "" || !strings.EqualFold(r.Host, s.cfg.ViewHost())) {
			http.Error(w, "misdirected request", http.StatusMisdirectedRequest)
			return
		}
		limited.ServeHTTP(w, r)
	})
}

func (s *Server) httpsConfiguredHost(host string) bool {
	if strings.HasPrefix(strings.ToLower(s.cfg.PublicURL), "https://") && strings.EqualFold(host, s.cfg.Host()) {
		return true
	}
	return s.cfg.View.URL != "" && strings.HasPrefix(strings.ToLower(s.cfg.View.URL), "https://") && strings.EqualFold(host, s.cfg.ViewHost())
}

func (l *requestLimits) allow(ip string) (time.Duration, bool) {
	now := l.now()
	l.mu.Lock()
	defer l.mu.Unlock()

	if !now.Before(l.nextCleanup) {
		for key, c := range l.clients {
			if now.Sub(c.lastSeen) >= l.clientExpiry {
				delete(l.clients, key)
			}
		}
		l.nextCleanup = now.Add(time.Minute)
	}
	c, exists := l.clients[ip]
	if !exists {
		if len(l.clients) >= l.maxClients {
			return time.Minute, false
		}
		c = clientRate{tokens: float64(l.burst), updated: now}
	}
	c.lastSeen = now
	elapsed := now.Sub(c.updated).Seconds()
	c.tokens = math.Min(float64(l.burst), c.tokens+elapsed*float64(l.perMinute)/60)
	c.updated = now
	if c.tokens < 1 {
		wait := time.Duration(math.Ceil((1 - c.tokens) * 60 / float64(l.perMinute) * float64(time.Second)))
		if wait < time.Second {
			wait = time.Second
		}
		l.clients[ip] = c
		return wait, false
	}
	c.tokens--
	l.clients[ip] = c
	return 0, true
}

func remoteIP(remoteAddr string) string {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err == nil {
		if ip := net.ParseIP(host); ip != nil {
			return ip.String()
		}
	}
	if ip := net.ParseIP(remoteAddr); ip != nil {
		return ip.String()
	}
	return strings.TrimSpace(remoteAddr)
}

func strconvSeconds(d time.Duration) string {
	seconds := int64(math.Ceil(d.Seconds()))
	if seconds < 1 {
		seconds = 1
	}
	return strconv.FormatInt(seconds, 10)
}

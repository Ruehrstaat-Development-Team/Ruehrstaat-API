package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"ruehrstaat-backend/api"
	"ruehrstaat-backend/auth"
	"ruehrstaat-backend/auth/discord"
	"ruehrstaat-backend/cache"
	"ruehrstaat-backend/constants"
	"ruehrstaat-backend/db"
	"ruehrstaat-backend/logging"
	"ruehrstaat-backend/services/moria"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/getsentry/sentry-go"
	sentrygin "github.com/getsentry/sentry-go/gin"
	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
	_ "github.com/joho/godotenv/autoload"
)

var log = logging.Logger{Package: "main"}
var useSentry = false

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()
	log.Println("Launching: " + constants.APP_NAME + " v" + constants.APP_VERSION)
	log.Println("Starting up...")

	// load env vars
	err := godotenv.Load(".env")
	if err != nil {
		log.Println("Couldn't load .env file")
	}

	server, err := setup()
	if err != nil {
		log.Printf("Startup failed: %v", err)
		panic(err)
	}

	serverErr := make(chan error, 1)
	go func() {
		serverErr <- server.ListenAndServe()
	}()

	select {
	case <-ctx.Done():
		log.Println("Shutdown signal received")
	case err := <-serverErr:
		if err != nil && err != http.ErrServerClosed {
			panic(err)
		}
		return
	}

	if os.Getenv("CRON") == "true" {
		log.Println("Shutting down cron system...")
		//cron.StopCron()
	}

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer shutdownCancel()
	if err := server.Shutdown(shutdownCtx); err != nil {
		log.Printf("Shutdown error: %v", err)
	}

	log.Println("Shutdown complete")
}

func setup() (*http.Server, error) {
	log.Println("Startup phase: sentry")
	sentryEnv := getSentryEnv()
	sentryDSN := os.Getenv("SENTRY_DSN")
	if sentryDSN == "" {
		log.Println("No Sentry DSN provided. Sentry will not be initialized.")
		useSentry = false
	} else {
		samplingRate := 1.0
		if samplingRateStr := os.Getenv("SENTRY_SAMPLING_RATE"); samplingRateStr != "" {
			if parsed, err := strconv.ParseFloat(samplingRateStr, 64); err == nil {
				samplingRate = parsed
			}
		}

		useSentry = true
		if err := sentry.Init(sentry.ClientOptions{
			Dsn:              sentryDSN,
			Environment:      sentryEnv,
			Release:          fmt.Sprintf("v%s", constants.APP_VERSION),
			EnableTracing:    true,
			TracesSampleRate: samplingRate,
			SampleRate:       samplingRate,
		}); err != nil {
			return nil, fmt.Errorf("startup phase sentry: %w", err)
		}
	}
	log.Println("Startup phase complete: sentry")

	log.Println("Startup phase: auth providers")
	discord.Initialize()
	auth.InitializeWebauthn()
	log.Println("Startup phase complete: auth providers")

	log.Println("Startup phase: security audit log")
	if err := logging.InitSecurityAuditLog(); err != nil {
		log.Printf("Warning: Failed to initialize security audit log: %v", err)
	}
	log.Println("Startup phase complete: security audit log")

	if err := runStartupPhase("database", db.Initialize); err != nil {
		return nil, err
	}

	if err := runStartupPhase("redis", cache.Initialize); err != nil {
		return nil, err
	}

	if os.Getenv("MORIA_ENABLED") == "true" {
		log.Println("Startup phase: moria")
		moria.InitMoria(os.Getenv("MORIA_URL"), os.Getenv("MORIA_TOKEN"))
		log.Println("Startup phase complete: moria")
	}

	log.Println("Startup phase: http server")
	r := gin.New()
	trustedProxies, trustedProxyErr := auth.TrustedProxiesFromEnv()
	if trustedProxyErr != nil {
		return nil, fmt.Errorf("startup phase http server: %w", trustedProxyErr)
	}
	if err := r.SetTrustedProxies(trustedProxies); err != nil {
		return nil, fmt.Errorf("startup phase http server: %w", err)
	}
	if useSentry {
		r.Use(sentrygin.New(sentrygin.Options{Repanic: true}))
	}
	r.Use(recovery())
	r.Use(cors())
	r.Use(gin.Logger())
	r.Use(errorLogger())

	api.RegisterRoutes(&r.RouterGroup)
	/*
		if os.Getenv("CRON") == "true" {
			go cron.RunCron()
		} else {
			log.Println("Cron system disabled")
		}*/

	log.Println("Startup phase complete: http server")
	log.Println("Listening on :8000")
	return &http.Server{Addr: ":8000", Handler: r}, nil
}

func runStartupPhase(name string, fn func() error) error {
	log.Printf("Startup phase: %s", name)
	if err := fn(); err != nil {
		return fmt.Errorf("startup phase %s: %w", name, err)
	}
	log.Printf("Startup phase complete: %s", name)
	return nil
}

func getSentryEnv() string {
	env := os.Getenv("SENTRY_ENV")
	if env == "" {
		if gin.Mode() == gin.ReleaseMode {
			env = "production"
		} else {
			env = "development"
		}
	}

	return env
}

func recovery() gin.HandlerFunc {
	return func(c *gin.Context) {
		defer func() {
			if rec := recover(); rec != nil {
				stackTrace := make([]byte, 4096) // 4KB should be sufficient
				length := runtime.Stack(stackTrace, true)
				stackTraceString := string(stackTrace[:length])

				// Use hub from the Gin context
				if hub := sentrygin.GetHubFromContext(c); useSentry && hub != nil {
					hub.WithScope(func(scope *sentry.Scope) {
						scope.SetRequest(sanitizeRequestForSentry(c.Request))
						scope.SetLevel(sentry.LevelFatal) // Setting the level to fatal as it's a panic
						scope.SetExtra("stacktrace", stackTraceString)

						// Check if the recovered value is an error
						if err, ok := rec.(error); ok {
							// If it is an error, capture it with stack trace
							hub.CaptureException(err)
							if gin.Mode() == gin.DebugMode {
								log.Printf("Panic: %s\n%s", err.Error(), stackTraceString)
							} else {
								log.Printf("Panic: %s", err.Error())
							}
						} else {
							// If it is not an error, capture it as a message along with the stack trace
							errMessage := fmt.Sprintf("Panic: %+v", rec)
							hub.CaptureMessage(errMessage)
							if gin.Mode() == gin.DebugMode {
								log.Printf("%s\n%s", errMessage, stackTraceString)
							} else {
								log.Printf("%s", errMessage)
							}
						}
					})
				} else {
					// If Sentry hub is not present, fall back to standard logging
					if err, ok := rec.(error); ok {
						if gin.Mode() == gin.DebugMode {
							log.Printf("Panic: %s\n%s", err.Error(), stackTraceString)
						} else {
							log.Printf("Panic: %s", err.Error())
						}
					} else {
						if gin.Mode() == gin.DebugMode {
							log.Printf("Panic: %+v\n%s", rec, stackTraceString)
						} else {
							log.Printf("Panic: %+v", rec)
						}
					}
				}

				// Respond with error
				c.JSON(500, gin.H{"error": "Internal Server Error"})
			}
		}()

		c.Next()
	}
}

type responseBodyWriter struct {
	gin.ResponseWriter
	body *bytes.Buffer
}

func (w *responseBodyWriter) Write(b []byte) (int, error) {
	w.body.Write(b)
	return w.ResponseWriter.Write(b)
}

func errorLogger() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Replace the existing ResponseWriter with our own
		blw := &responseBodyWriter{body: &bytes.Buffer{}, ResponseWriter: c.Writer}
		c.Writer = blw

		// Process the request
		c.Next()

		statusCode := c.Writer.Status()
		if statusCode >= 400 {
			// Determine the error message
			errorMessage := "Unknown error"
			if len(c.Errors) > 0 {
				errorMessage = c.Errors.String()
			}

			if shouldCaptureSentryEvent(statusCode) {
				if hub := sentrygin.GetHubFromContext(c); useSentry && hub != nil {
					hub.WithScope(func(scope *sentry.Scope) {
						// Set the scope for the current context
						scope.SetRequest(sanitizeRequestForSentry(c.Request))
						scope.SetExtra("method", c.Request.Method)
						scope.SetExtra("url", requestPathForSentry(c.Request))
						scope.SetExtra("statusCode", statusCode)
						scope.SetExtra("userAgent", c.Request.UserAgent())
						scope.SetExtra("clientIP", c.ClientIP())

						if user := auth.Extract(c); user != nil {
							scope.SetUser(sentry.User{ID: user.ID.String(), Email: user.Email, IPAddress: c.ClientIP(), Username: fmt.Sprintf("%s/%s", user.Nickname, user.CmdrName)})
						}

						level := sentry.LevelWarning
						if gin.Mode() == gin.DebugMode {
							level = sentry.LevelError
						}
						scope.SetLevel(level)

						// Build and capture the message
						message := fmt.Sprintf(
							"Error %d: %s\nMethod: %s\nPath: %s\nClient IP: %s\nUser Agent: %s\nError Message: %s",
							statusCode,
							c.Request.URL.Path,
							c.Request.Method,
							requestPathForSentry(c.Request),
							c.ClientIP(),
							c.Request.UserAgent(),
							errorMessage,
						)
						hub.CaptureMessage(message)
					})
					return
				}
			}

			log.Printf("Error %d: %s\n", statusCode, errorMessage)
		}
	}
}

func shouldCaptureSentryEvent(statusCode int) bool {
	return statusCode >= 500
}

func cors() gin.HandlerFunc {
	return func(c *gin.Context) {
		corsAllowedOrigin := strings.TrimSpace(os.Getenv("CORS_ALLOWED_ORIGINS"))

		if corsAllowedOrigin == "*" {
			c.Writer.Header().Set("Access-Control-Allow-Origin", "*")
			c.Writer.Header().Set("Access-Control-Allow-Credentials", "false")
		} else {
			allowedOrigins := auth.AllowedOriginsFromEnv("CORS_ALLOWED_ORIGINS")
			if origin := c.Request.Header.Get("Origin"); auth.OriginAllowed(origin, allowedOrigins) {
				c.Writer.Header().Set("Access-Control-Allow-Origin", origin)
				c.Writer.Header().Set("Vary", "Origin")
				c.Writer.Header().Set("Access-Control-Allow-Credentials", "true")
			}
		}

		c.Writer.Header().Set("Access-Control-Allow-Methods", "GET, PATCH, POST, PUT, DELETE, OPTIONS")
		c.Writer.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type, Baggage, Accept, Sentry-Trace, X-RST-User-Id, X-RST-Token, X-RST-Client-Id, X-RST-Client-Secret")
		c.Writer.Header().Set("Access-Control-Expose-Headers", "Authorization, Content-Type")

		//log.Printf("Request: %s %s", c.Request.Method, c.Request.URL.Path)

		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(200)
			return
		}

		c.Next()
	}
}

func sanitizeRequestForSentry(r *http.Request) *http.Request {
	if r == nil {
		return nil
	}

	sanitized := r.Clone(r.Context())
	sanitized.URL = cloneURLWithoutQuery(r.URL)
	sanitized.RequestURI = requestPathForSentry(r)
	sanitized.Header = sanitizeHeadersForSentry(r.Header)
	sanitized.Body = io.NopCloser(strings.NewReader(""))
	sanitized.GetBody = nil
	sanitized.ContentLength = 0
	sanitized.Form = nil
	sanitized.PostForm = nil
	sanitized.MultipartForm = nil

	return sanitized
}

func sanitizeHeadersForSentry(headers http.Header) http.Header {
	if headers == nil {
		return nil
	}

	sanitized := headers.Clone()
	for _, header := range []string{"Authorization", "Cookie", "Set-Cookie", "X-API-Key", "Proxy-Authorization", "X-RST-Token", "X-RST-Client-Secret", "X-RST-Client-Id", "X-RST-User-Id"} {
		sanitized.Del(header)
	}

	return sanitized
}

func requestPathForSentry(r *http.Request) string {
	if r == nil || r.URL == nil {
		return ""
	}

	if r.URL.Path != "" {
		return r.URL.Path
	}

	return "/"
}

func cloneURLWithoutQuery(u *url.URL) *url.URL {
	if u == nil {
		return nil
	}

	clone := *u
	clone.RawQuery = ""
	clone.ForceQuery = false
	clone.Fragment = ""

	return &clone
}

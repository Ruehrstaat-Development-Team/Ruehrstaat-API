package main

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/signal"
	"ruehrstaat-backend/api"
	"ruehrstaat-backend/auth"
	"ruehrstaat-backend/auth/discord"
	"ruehrstaat-backend/cache"
	"ruehrstaat-backend/constants"
	"ruehrstaat-backend/db"
	"ruehrstaat-backend/logging"
	"runtime"

	"github.com/getsentry/sentry-go"
	sentrygin "github.com/getsentry/sentry-go/gin"
	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
	_ "github.com/joho/godotenv/autoload"
)

var log = logging.Logger{Package: "main"}

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

	go setup()

	<-ctx.Done()

	if os.Getenv("CRON") == "true" {
		log.Println("Shutting down cron system...")
		//cron.StopCron()
	}

	log.Println("Shutdown complete")
}

func setup() {

	if err := sentry.Init(sentry.ClientOptions{
		Dsn:                os.Getenv("SENTRY_DSN"),
		Environment:        getSentryEnv(),
		Release:            fmt.Sprintf("v%s", constants.APP_VERSION),
		EnableTracing:      true,
		TracesSampleRate:   1.0,
		ProfilesSampleRate: 1.0,
	}); err != nil {
		panic(err)
	}

	discord.Initialize()
	auth.InitializeWebauthn()

	db.Initialize()
	cache.Initialize()

	r := gin.New()
	r.Use(sentrygin.New(sentrygin.Options{
		Repanic: true,
	}))
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

	err := r.Run(":8080")
	if err != nil {
		log.Println("Error: ", err)
	}
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
				if hub := sentrygin.GetHubFromContext(c); hub != nil {
					hub.WithScope(func(scope *sentry.Scope) {
						scope.SetRequest(c.Request)
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
		if statusCode >= 400 { // Capture all 4xx and 5xx errors
			// Determine the error message
			errorMessage := "Unknown error"
			if len(c.Errors) > 0 {
				errorMessage = c.Errors.String()
			}

			// Get the body content
			responseBody := blw.body.String()

			// Use hub from the Gin context
			if hub := sentrygin.GetHubFromContext(c); hub != nil {
				hub.WithScope(func(scope *sentry.Scope) {
					// Set the scope for the current context
					scope.SetRequest(c.Request)
					scope.SetExtra("method", c.Request.Method)
					scope.SetExtra("url", c.Request.URL.String())
					scope.SetExtra("headers", c.Request.Header)
					scope.SetExtra("statusCode", statusCode)
					scope.SetExtra("userAgent", c.Request.UserAgent())
					scope.SetExtra("clientIP", c.ClientIP())
					scope.SetExtra("responseBody", responseBody)

					// Determine the level of logging based on the status code
					level := sentry.LevelInfo
					if statusCode >= 500 {
						if gin.Mode() == gin.DebugMode {
							level = sentry.LevelError
						} else {
							level = sentry.LevelWarning
						}
					} else if statusCode >= 400 {
						if gin.Mode() == gin.DebugMode {
							level = sentry.LevelInfo
						} else {
							level = sentry.LevelDebug
						}
					}
					scope.SetLevel(level)

					// Build and capture the message
					message := fmt.Sprintf(
						"Error %d: %s\nMethod: %s\nPath: %s\nClient IP: %s\nUser Agent: %s\nError Message: %s\nResponse Body: %s",
						statusCode,
						c.Request.URL.Path,
						c.Request.Method,
						c.Request.URL.String(),
						c.ClientIP(),
						c.Request.UserAgent(),
						errorMessage,
						responseBody,
					)
					hub.CaptureMessage(message)
				})
			} else {
				// If hub is not present, fall back to standard logging
				log.Printf("Error %d: %s\n", statusCode, errorMessage)
			}
		}
	}
}

func cors() gin.HandlerFunc {
	return func(c *gin.Context) {
		corsAllowedOrigin := os.Getenv("CORS_ALLOWED_ORIGINS")

		if corsAllowedOrigin == "*" {
			requestDomain := c.Request.Header.Get("Origin")
			c.Writer.Header().Set("Access-Control-Allow-Origin", requestDomain)
		} else {
			c.Writer.Header().Set("Access-Control-Allow-Origin", corsAllowedOrigin)
		}

		c.Writer.Header().Set("Access-Control-Allow-Credentials", "true")
		c.Writer.Header().Set("Access-Control-Allow-Methods", "GET, PATCH, POST, PUT, DELETE, OPTIONS")
		c.Writer.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type, Baggage, Accept, Sentry-Trace")
		c.Writer.Header().Set("Access-Control-Expose-Headers", "Authorization, Content-Type")

		//log.Printf("Request: %s %s", c.Request.Method, c.Request.URL.Path)

		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(200)
			return
		}

		c.Next()
	}
}

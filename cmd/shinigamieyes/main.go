package main

import (
    "context"
    "fmt"
    "github.com/bluesky-social/indigo/atproto/identity"
    "github.com/bluesky-social/indigo/atproto/identity/redisdir"
    "github.com/bluesky-social/indigo/automod/consumer"
    "github.com/carlmjohnson/versioninfo"
    "github.com/joho/godotenv"
    "github.com/urfave/cli/v2"
    "golang.org/x/time/rate"
    "io"
    "log/slog"
    "net/http"
    "os"
    "runtime"
    "strings"
    "time"
)

func main() {
	err := godotenv.Load()
	if err != nil {
		slog.Error("Error loading .env file")
	}
	if err := run(os.Args); err != nil {
		slog.Error("exiting", "err", err)
		os.Exit(-1)
	}
}

func run(args []string) error {

	app := cli.App{
		Name:    "shinigamieyes",
		Usage:   "an experimental auto-labeler created by @alli.gay",
		Version: versioninfo.Short(),
	}

	app.Flags = []cli.Flag{
		&cli.StringFlag{
			Name:    "atp-relay-host",
			Usage:   "hostname and port of Relay to subscribe to",
			Value:   "wss://bsky.network",
			EnvVars: []string{"ATP_RELAY_HOST", "ATP_BGS_HOST"},
		},
		&cli.StringFlag{
			Name:    "atp-plc-host",
			Usage:   "method, hostname, and port of PLC registry",
			Value:   "https://plc.directory",
			EnvVars: []string{"ATP_PLC_HOST"},
		},
		&cli.StringFlag{
			Name:    "atp-bsky-host",
			Usage:   "method, hostname, and port of bsky API (appview) service. does not use auth",
			Value:   "https://public.api.bsky.app",
			EnvVars: []string{"ATP_BSKY_HOST"},
		},
		&cli.StringFlag{
			Name:    "atp-ozone-host",
			Usage:   "method, hostname, and port of ozone instance. requires ozone-admin-token as well",
			Value:   "https://mod.bsky.app",
			EnvVars: []string{"ATP_OZONE_HOST", "ATP_MOD_HOST"},
		},
		&cli.StringFlag{
			Name:    "ozone-did",
			Usage:   "DID of account to attribute ozone actions to",
			EnvVars: []string{"SHINIGAMI_OZONE_DID"},
		},
		&cli.StringFlag{
			Name:    "perspective-api-key",
			Usage:   "api key for Google's perspective",
			EnvVars: []string{"SHINIGAMI_PERSPECTIVE_API_KEY"},
		},
		&cli.StringFlag{
			Name:    "ozone-admin-token",
			Usage:   "admin authentication password for mod service",
			EnvVars: []string{"SHINIGAMI_OZONE_AUTH_ADMIN_TOKEN", "SHINIGAMI_MOD_AUTH_ADMIN_TOKEN"},
		},
		&cli.StringFlag{
			Name:  "redis-url",
			Usage: "redis connection URL",
			// redis://<user>:<pass>@localhost:6379/<db>
			// redis://localhost:6379/0
			EnvVars: []string{"SHINIGAMI_REDIS_URL"},
		},
		&cli.IntFlag{
			Name:    "plc-rate-limit",
			Usage:   "max number of requests per second to PLC registry",
			Value:   100,
			EnvVars: []string{"SHINIGAMI_PLC_RATE_LIMIT"},
		},
		&cli.StringFlag{
			Name:    "sets-json-path",
			Usage:   "file path of JSON file containing static sets",
			EnvVars: []string{"SHINIGAMI_SETS_JSON_PATH"},
		},
		&cli.StringFlag{
			Name:    "ruleset",
			Usage:   "which ruleset config to use: default, no-blobs, only-blobs",
			EnvVars: []string{"SHINIGAMI_RULESET"},
		},
		&cli.StringFlag{
			Name:    "log-level",
			Usage:   "log verbosity level (eg: warn, info, debug)",
			EnvVars: []string{"SHINIGAMI_LOG_LEVEL", "LOG_LEVEL"},
		},
		&cli.StringFlag{
			Name:    "ratelimit-bypass",
			Usage:   "HTTP header to bypass ratelimits",
			EnvVars: []string{"SHINIGAMI_RATELIMIT_BYPASS", "RATELIMIT_BYPASS"},
		},
		&cli.IntFlag{
			Name:    "firehose-parallelism",
			Usage:   "force a fixed number of parallel firehose workers. default (or 0) for auto-scaling; 200 works for a large instance",
			EnvVars: []string{"SHINIGAMI_FIREHOSE_PARALLELISM"},
		},
		&cli.DurationFlag{
			Name:    "report-dupe-period",
			Usage:   "time period within which automod will not re-report an account for the same reasonType",
			EnvVars: []string{"SHINIGAMI_REPORT_DUPE_PERIOD"},
			Value:   1 * 24 * time.Hour,
		},
		&cli.IntFlag{
			Name:    "quota-mod-report-day",
			Usage:   "number of reports automod can file per day, for all subjects and types combined (circuit breaker)",
			EnvVars: []string{"SHINIGAMI_QUOTA_MOD_REPORT_DAY"},
			Value:   10000,
		},
		&cli.IntFlag{
			Name:    "quota-mod-takedown-day",
			Usage:   "number of takedowns automod can action per day, for all subjects combined (circuit breaker)",
			EnvVars: []string{"SHINIGAMI_QUOTA_MOD_TAKEDOWN_DAY"},
			Value:   200,
		},
		&cli.IntFlag{
			Name:    "quota-mod-action-day",
			Usage:   "number of misc actions automod can do per day, for all subjects combined (circuit breaker)",
			EnvVars: []string{"SHINIGAMI_QUOTA_MOD_ACTION_DAY"},
			Value:   2000,
		},
		&cli.DurationFlag{
			Name:    "record-event-timeout",
			Usage:   "total processing time for record events (including setup, rules, and persisting)",
			EnvVars: []string{"SHINIGAMI_RECORD_EVENT_TIMEOUT"},
			Value:   30 * time.Second,
		},
		&cli.DurationFlag{
			Name:    "identity-event-timeout",
			Usage:   "total processing time for identity and account events (including setup, rules, and persisting)",
			EnvVars: []string{"SHINIGAMI_IDENTITY_EVENT_TIMEOUT"},
			Value:   10 * time.Second,
		},
		&cli.DurationFlag{
			Name:    "ozone-event-timeout",
			Usage:   "total processing time for ozone events (including setup, rules, and persisting)",
			EnvVars: []string{"SHINIGAMI_OZONE_EVENT_TIMEOUT"},
			Value:   30 * time.Second,
		},
	}

	app.Commands = []*cli.Command{
		runCmd,
	}

	return app.Run(args)
}

func configLogger(cctx *cli.Context, writer io.Writer) *slog.Logger {
	var level slog.Level
	switch strings.ToLower(cctx.String("log-level")) {
	case "error":
		level = slog.LevelError
	case "warn":
		level = slog.LevelWarn
	case "info":
		level = slog.LevelInfo
	case "debug":
		level = slog.LevelDebug
	default:
		level = slog.LevelInfo
	}
	logger := slog.New(slog.NewJSONHandler(writer, &slog.HandlerOptions{
		Level: level,
	}))
	slog.SetDefault(logger)
	return logger
}

func configDirectory(cctx *cli.Context) (identity.Directory, error) {
	baseDir := identity.BaseDirectory{
		PLCURL: cctx.String("atp-plc-host"),
		HTTPClient: http.Client{
			Timeout: time.Second * 15,
		},
		PLCLimiter:            rate.NewLimiter(rate.Limit(cctx.Int("plc-rate-limit")), 1),
		TryAuthoritativeDNS:   true,
		SkipDNSDomainSuffixes: []string{".bsky.social", ".staging.bsky.dev"},
	}
	var dir identity.Directory
	if cctx.String("redis-url") != "" {
		rdir, err := redisdir.NewRedisDirectory(&baseDir, cctx.String("redis-url"), time.Hour*24, time.Minute*2, time.Minute*5, 10_000)
		if err != nil {
			return nil, err
		}
		dir = rdir
	} else {
		cdir := identity.NewCacheDirectory(&baseDir, 1_500_000, time.Hour*24, time.Minute*2, time.Minute*5)
		dir = &cdir
	}
	return dir, nil
}

var runCmd = &cli.Command{
	Name:  "run",
	Usage: "run the hepa daemon",
	Flags: []cli.Flag{
		&cli.StringFlag{
			Name:    "metrics-listen",
			Usage:   "IP or address, and port, to listen on for metrics APIs",
			Value:   ":3989",
			EnvVars: []string{"SHINIGAMI_METRICS_LISTEN"},
		},
	},

	Action: func(cctx *cli.Context) error {
		ctx := context.Background()
		logger := configLogger(cctx, os.Stdout)

		dir, err := configDirectory(cctx)
		if err != nil {
			return fmt.Errorf("failed to configure identity directory: %v", err)
		}

		srv, err := NewServer(
			dir,
			Config{
				Logger:               logger,
				BskyHost:             cctx.String("atp-bsky-host"),
				OzoneHost:            cctx.String("atp-ozone-host"),
				OzoneDID:             cctx.String("ozone-did"),
				OzoneAdminToken:      cctx.String("ozone-admin-token"),
				PerspectiveApiKey:      cctx.String("perspective-api-key"),
				SetsFileJSON:         cctx.String("sets-json-path"),
				RedisURL:             cctx.String("redis-url"),
				RatelimitBypass:      cctx.String("ratelimit-bypass"),
				RulesetName:          cctx.String("ruleset"),
				ReportDupePeriod:     cctx.Duration("report-dupe-period"),
				QuotaModReportDay:    cctx.Int("quota-mod-report-day"),
				QuotaModTakedownDay:  cctx.Int("quota-mod-takedown-day"),
				QuotaModActionDay:    cctx.Int("quota-mod-action-day"),
				RecordEventTimeout:   cctx.Duration("record-event-timeout"),
				IdentityEventTimeout: cctx.Duration("identity-event-timeout"),
				OzoneEventTimeout:    cctx.Duration("ozone-event-timeout"),
			},
		)
		if err != nil {
			return fmt.Errorf("failed to construct server: %v", err)
		}

		// ozone event consumer (if configured)
		if srv.Engine.OzoneClient != nil {
			oc := consumer.OzoneConsumer{
				Logger:      logger.With("subsystem", "ozone-consumer"),
				RedisClient: srv.RedisClient,
				OzoneClient: srv.Engine.OzoneClient,
				Engine:      srv.Engine,
			}

			go func() {
				if err := oc.Run(ctx); err != nil {
					slog.Error("ozone consumer failed", "err", err)
				}
			}()

			go func() {
				if err := oc.RunPersistCursor(ctx); err != nil {
					slog.Error("ozone cursor routine failed", "err", err)
				}
			}()
		}

		// prometheus HTTP endpoint: /metrics
		go func() {
			runtime.SetBlockProfileRate(10)
			runtime.SetMutexProfileFraction(10)
			if err := srv.RunMetrics(cctx.String("metrics-listen")); err != nil {
				slog.Error("failed to start metrics endpoint", "error", err)
				panic(fmt.Errorf("failed to start metrics endpoint: %w", err))
			}
		}()

		// firehose event consumer (note this is actually mandatory)
		relayHost := cctx.String("atp-relay-host")
		if relayHost != "" {
			fc := consumer.FirehoseConsumer{
				Engine:      srv.Engine,
				Logger:      logger.With("subsystem", "firehose-consumer"),
				Host:        cctx.String("atp-relay-host"),
				Parallelism: cctx.Int("firehose-parallelism"),
				RedisClient: srv.RedisClient,
			}

			go func() {
				if err := fc.RunPersistCursor(ctx); err != nil {
					slog.Error("cursor routine failed", "err", err)
				}
			}()

			if err := fc.Run(ctx); err != nil {
				return fmt.Errorf("failure consuming and processing firehose: %w", err)
			}
		}

		return nil
	},
}
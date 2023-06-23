package cmd

import (
	"context"
	"errors"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/els0r/goProbe/cmd/global-query/pkg/conf"
	"github.com/els0r/goProbe/pkg/api/globalquery/server"
	"github.com/els0r/goProbe/pkg/logging"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// serverCmd represents the server command
var serverCmd = &cobra.Command{
	Use:   "server",
	Short: "Run global-query in server mode",
	Long:  "Run global-query in server mode",
	RunE:  serverEntrypoint,
}

func init() {
	rootCmd.AddCommand(serverCmd)

	serverCmd.Flags().String(conf.ServerAddr, conf.DefaultServerAddr, "address to which the server binds")
	serverCmd.Flags().Duration(conf.ServerShutdownGracePeriod, conf.DefaultServerShutdownGracePeriod, "duration the server will wait during shutdown before forcing shutdown")

	_ = viper.BindPFlags(serverCmd.Flags())
}

func serverEntrypoint(cmd *cobra.Command, args []string) error {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM, os.Interrupt)
	defer stop()

	logger := logging.FromContext(ctx)

	hostListResolver, err := initHostListResolver()
	if err != nil {
		logger.Errorf("failed to prepare query: %v", err)
		return err
	}

	// get the workload provider
	querier, err := initQuerier()
	if err != nil {
		logger.Errorf("failed to set up queriers: %v", err)
		return err
	}

	// set up the API server
	addr := viper.GetString(conf.ServerAddr)
	apiServer := server.NewServer(addr, hostListResolver, querier,
		// Set the release mode of GIN depending on the log level
		server.WithDebugMode(
			logging.LevelFromString(viper.GetString(conf.LogLevel)) == logging.LevelDebug,
		),
	)

	// initializing the server in a goroutine so that it won't block the graceful
	// shutdown handling below
	logger.With("addr", addr).Info("starting API server")
	go func() {
		err = apiServer.Serve()
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Fatalf("listen: %v", err)
		}
	}()

	// listen for the interrupt signal
	<-ctx.Done()

	// restore default behavior on the interrupt signal and notify user of shutdown.
	stop()
	logger.Info("shutting down server gracefully")

	// the context is used to inform the server it has ShutdownGracePeriod to wrap up the requests it is
	// currently handling
	ctx, cancel := context.WithTimeout(context.Background(), viper.GetDuration(conf.ServerShutdownGracePeriod))
	defer cancel()

	// shut down running resources, forcibly if need be
	err = apiServer.Shutdown(ctx)
	if err != nil {
		logger.Errorf("forced shut down of API server: %v", err)
	}

	logger.Info("shut down complete")
	return nil
}

package server

import (
	"github.com/els0r/goProbe/cmd/goProbe/config"
	gpapi "github.com/els0r/goProbe/pkg/api/goprobe"
	"github.com/els0r/goProbe/pkg/api/server"
	"github.com/els0r/goProbe/pkg/capture"
	"github.com/els0r/goProbe/pkg/defaults"
	"github.com/els0r/goProbe/pkg/goprobe/writeout"
)

// Server runs a goprobe API server
type Server struct {
	// goprobe specific variables
	dbPath          string
	captureManager  *capture.Manager
	writeoutHandler *writeout.Handler

	*server.DefaultServer
}

// SetDBPath sets the path to the database directory
func (server *Server) SetDBPath(path string) *Server {
	server.dbPath = path
	return server
}

// New creates a new goprobe API server
func New(addr string, captureManager *capture.Manager, opts ...server.Option) *Server {
	server := &Server{
		dbPath:         defaults.DBPath,
		captureManager: captureManager,
		DefaultServer:  server.NewDefault(config.ServiceName, addr, opts...),
	}

	server.registerRoutes()

	return server
}

const ifaceKey = "interface"

func (server *Server) registerRoutes() {
	router := server.Router()

	// query
	router.GET(gpapi.QueryRoute, server.postQuery)  // support for URL-encoded form data GET requests
	router.POST(gpapi.QueryRoute, server.postQuery) // support for JSON or form-data body POST requests

	// stats
	statsRoutes := router.Group(gpapi.StatusRoute)
	statsRoutes.GET("", server.getStatus)
	statsRoutes.GET("/:"+ifaceKey, server.getStatus)

	// config
	configRoutes := router.Group(gpapi.ConfigRoute)
	configRoutes.GET("", server.getConfig)
	configRoutes.GET("/:"+ifaceKey, server.getConfig)
	configRoutes.PUT("", server.putConfig)
}

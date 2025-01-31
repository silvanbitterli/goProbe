package distributed

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/els0r/goProbe/cmd/global-query/pkg/hosts"
	"github.com/els0r/goProbe/pkg/query"
	"github.com/els0r/goProbe/pkg/results"
	"github.com/els0r/goProbe/pkg/types"
	"github.com/els0r/telemetry/logging"
)

// QueryRunner denotes a query runner / executor, wrapping a Querier interface instance with
// other fields required to perform a distributed query
type QueryRunner struct {
	resolver hosts.Resolver
	querier  Querier

	maxConcurrent int
}

// QueryOption configures the query runner
type QueryOption func(*QueryRunner)

// WithMaxConcurrent limits the amount of hosts that are queried concurrently.
// If it isn't set, every hosts in the list is queried in a separate goroutine
func WithMaxConcurrent(n int) QueryOption {
	return func(qr *QueryRunner) {
		qr.maxConcurrent = n
	}
}

// NewQueryRunner instantiates a new distributed query runner
func NewQueryRunner(resolver hosts.Resolver, querier Querier, opts ...QueryOption) (qr *QueryRunner) {
	qr = &QueryRunner{
		resolver: resolver,
		querier:  querier,
	}
	for _, opt := range opts {
		opt(qr)
	}
	return
}

// Run executes / runs the query and creates the final result structure
func (q *QueryRunner) Run(ctx context.Context, args *query.Args) (*results.Result, error) {
	// use a copy of the arguments, since some fields are modified by the querier
	queryArgs := *args

	// a distributed query, by definition, requires a list of hosts to query
	if queryArgs.QueryHosts == "" {
		return nil, fmt.Errorf("couldn't prepare query: list of target hosts is empty")
	}

	// check if the statement can be created
	stmt, err := queryArgs.Prepare()
	if err != nil {
		return nil, fmt.Errorf("failed to prepare query statement: %w", err)
	}

	hostList, err := q.resolver.Resolve(ctx, queryArgs.QueryHosts)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve host list: %w", err)
	}

	// log the query
	logger := logging.Logger().With("hosts", hostList)

	// query pipeline setup
	// sets up a fan-out, fan-in query processing pipeline
	numRunners := len(hostList)
	if q.maxConcurrent > 0 {
		numRunners = q.maxConcurrent
	}

	logger.With("runners", numRunners).Info("dispatching queries")

	finalResult := aggregateResults(ctx, stmt,
		runQueries(ctx, numRunners,
			prepareQueries(ctx, q.querier, hostList, &queryArgs),
		),
	)

	finalResult.End()

	// truncate results based on the limit
	if queryArgs.NumResults < uint64(len(finalResult.Rows)) {
		finalResult.Rows = finalResult.Rows[:queryArgs.NumResults]
	}
	finalResult.Summary.Hits.Displayed = len(finalResult.Rows)

	return finalResult, nil
}

// prepareQueries creates query workloads for all hosts in the host list and returns the channel it sends the
// workloads on
func prepareQueries(ctx context.Context, querier Querier, hostList hosts.Hosts, args *query.Args) <-chan *QueryWorkload {
	workloads := make(chan *QueryWorkload)

	go func(ctx context.Context) {
		logger := logging.FromContext(ctx)

		for _, host := range hostList {
			wl, err := querier.CreateQueryWorkload(ctx, host, args)
			if err != nil {
				logger.With("hostname", host).Errorf("failed to create workload: %v", err)
			}
			workloads <- wl
		}
		close(workloads)
	}(ctx)

	return workloads
}

// runQueries takes query workloads from the workloads channel, runs them, and returns a channel from which
// the results can be read
func runQueries(ctx context.Context, maxConcurrent int, workloads <-chan *QueryWorkload) <-chan *queryResponse {
	out := make(chan *queryResponse, maxConcurrent)

	wg := new(sync.WaitGroup)
	wg.Add(maxConcurrent)
	for i := 0; i < maxConcurrent; i++ {
		go func(ctx context.Context) {
			defer wg.Done()
			for {
				select {
				case <-ctx.Done():
					return
				case wl, open := <-workloads:
					if !open {
						return
					}

					res, err := wl.Runner.Run(ctx, wl.Args)
					if err != nil {
						err = fmt.Errorf("failed to run query: %w", err)
					}

					qr := &queryResponse{
						host:   wl.Host,
						result: res,
						err:    err,
					}

					out <- qr
				}
			}
		}(ctx)
	}
	go func() {
		wg.Wait()
		close(out)
	}()
	return out
}

// aggregateResults takes finished query workloads from the workloads channel, aggregates the result by merging the rows and summaries,
// and returns the final result. The `tracker` variable provides information about potential Run failures for individual hosts
func aggregateResults(ctx context.Context, stmt *query.Statement, queryResults <-chan *queryResponse) (finalResult *results.Result) {
	// aggregation
	finalResult = results.New()
	finalResult.Start()

	var rowMap = make(results.RowsMap)

	// tracker maps for meta info
	var ifaceMap = make(map[string]struct{})

	logger := logging.FromContext(ctx)

	defer func() {
		if len(rowMap) > 0 {
			finalResult.Rows = rowMap.ToRowsSorted(results.By(stmt.SortBy, stmt.Direction, stmt.SortAscending))
		}
		finalResult.End()
	}()

	for {
		select {
		case <-ctx.Done():
			return
		case qr, open := <-queryResults:
			if !open {
				return
			}
			logger := logger.With("hostname", qr.host)
			if qr.err != nil {
				// unwrap the error if it's possible
				var msg string

				uerr := errors.Unwrap(qr.err)
				if uerr != nil {
					msg = uerr.Error()
				} else {
					msg = qr.err.Error()
				}

				finalResult.HostsStatuses[qr.host] = results.Status{
					Code:    types.StatusError,
					Message: msg,
				}
				logger.Error(qr.err)
				continue
			}

			res := qr.result
			for host, status := range res.HostsStatuses {
				finalResult.HostsStatuses[host] = status
			}

			// merges the traffic data
			merged := rowMap.MergeRows(res.Rows)

			// merges the metadata
			for _, iface := range res.Summary.Interfaces {
				ifaceMap[iface] = struct{}{}
			}
			var ifaces = make([]string, 0, len(ifaceMap))
			for iface := range ifaceMap {
				ifaces = append(ifaces, iface)
			}

			finalResult.Summary.Interfaces = ifaces

			finalResult.Query = res.Query
			finalResult.Summary.First = res.Summary.First
			finalResult.Summary.Last = res.Summary.Last
			finalResult.Summary.Totals = finalResult.Summary.Totals.Add(res.Summary.Totals)

			// take the total from the query result. Since there may be overlap between the queries of two
			// different systems, the overlap has to be deducted from the total
			finalResult.Summary.Hits.Total += res.Summary.Hits.Total - merged
		}
	}
}

// QueryWorkload denotes an individual workload to perform a query on a remote host
type QueryWorkload struct {
	Host string

	Runner query.Runner
	Args   *query.Args
}

type queryResponse struct {
	host   string
	result *results.Result
	err    error
}

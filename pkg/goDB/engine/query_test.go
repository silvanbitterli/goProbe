package engine

import (
	"context"
	"errors"
	"io"
	"testing"

	"github.com/els0r/goProbe/pkg/query"
	"github.com/els0r/goProbe/pkg/types"
)

var (
	TestDB = "./testdb"
)

// Check that goQuery correctly handles the case where there is no output.
func TestEmptyOutput(t *testing.T) {

	var tests = []struct {
		name  string
		iface string
		query string
		opts  []query.Option
	}{
		{"eth1 talk_conv with condition - json output", "eth1", "talk_conv", []query.Option{query.WithFirst("-30000d"), query.WithCondition("dport < 100 & dport > 100"), query.WithFormat("json")}},
		// border case:
		// the value of the -l parameter forces us to consider the day 1456358400,
		// but day 1456358400 contains no blocks with timestamp < 1456428875
		// (= 1456428575 + DB_WRITEOUT_INTERVAL).
		{"eth1 raw - json output", "eth1", "raw", []query.Option{query.WithFirst("-30000d"), query.WithLast("1456428575"), query.WithFormat("json")}},
	}

	// run table-driven test
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {

			// create args
			a := query.NewArgs(test.query, test.iface, test.opts...)

			// execute query
			res, err := NewQueryRunner(TestDB).Run(context.Background(), a)
			if err != nil {
				t.Fatalf("execute query: %s", err)
			}

			result := res
			if result.Status.Code != types.StatusEmpty {
				t.Fatalf("unexpected status %q: %s", result.Status.Code, result.Status.Message)
			}
		})
	}
}

func TestSimpleQuery(t *testing.T) {

	// create args
	var tests = []struct {
		name  string
		iface string
		query string
		opts  []query.Option
	}{
		{
			"time query on eth1 - json output",
			"eth1",
			"time",
			[]query.Option{query.WithDirectionSum(), query.WithFirst("1456428000"), query.WithLast("1456473000"), query.WithNumResults(query.MaxResults), query.WithFormat("json")},
		},
	}

	// run table-driven test
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {

			// append output capture (to dev null, since this test only checks if the query
			// can be exectued

			// create args
			a := query.NewArgs(test.query, test.iface, test.opts...).AddOutputs(io.Discard)

			// execute query
			_, err := NewQueryRunner(TestDB).Run(context.Background(), a)
			if err != nil {
				t.Fatalf("execute query: %s", err)
			}
		})
	}
}

func TestInterfaceValidation(t *testing.T) {

	// create args
	var tests = []struct {
		iface       string
		expectedErr error
	}{
		{
			"",
			errors.New("interface list contains empty interface name"),
		},
		{
			"eth/0",
			errors.New("interface name `eth/0` is invalid"),
		},
		{
			"eth 0",
			errors.New("interface name `eth 0` is invalid"),
		},
		{
			"thisinterfacenameisfartoolongtobesupported",
			errors.New("interface name `thisinterfacenameisfartoolongtobesupported` is invalid"),
		},
		{
			"eth.15",
			nil,
		},
		{
			"eth:0",
			nil,
		},
	}

	// run table-driven test
	for _, test := range tests {
		t.Run(test.iface, func(t *testing.T) {
			err := validateIfaceName(test.iface)
			if test.expectedErr != nil {
				if err == nil || err.Error() != test.expectedErr.Error() {
					t.Fatalf("unexpected result for interface name validation: %s", err)
				}
			} else {
				if err != nil {
					t.Fatalf("unexpected result for interface name validation: %s", err)
				}
			}
		})
	}
}

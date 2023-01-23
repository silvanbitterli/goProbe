package query

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseTimestamp(t *testing.T) {
	var tests = []string{
		"-23d:4h:3m",
		"-23d4h8m3s",
		"1674492267",

		// special cases
		"2006-01-02T15:04:05-07:00", // RFC3339 test
		"Mon Jan 23 11:31:04 2023",  // ANSIC test
	}
	tests = append(tests, timeFormats[2:]...)

	for _, tStr := range tests {
		t.Run(tStr, func(t *testing.T) {
			tstamp, err := ParseTimeArgument(tStr)

			assert.Nil(t, err, "unexpected error: %v", err)
			assert.NotEqual(t, tstamp, 0, "expected non-zero timestam")
		})
	}
}

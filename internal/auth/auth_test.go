package auth_test

import (
	"errors"
	"net/http"
	"testing"

	"github.com/bootdotdev/learn-cicd-starter/internal/auth"
)

func TestGetAPIKey(t *testing.T) {
	malformedError := errors.New("malformed authorization header")

	tests := []struct {
		name   string
		input  http.Header
		output string
		err    error
	}{
		{
			name: "success",
			input: http.Header{
				"Authorization": []string{"ApiKey this-is-a-token"},
			},
			output: "this-is-a-token",
		},
		{
			name: "failure when no 'Authorization' header attached",
			input: http.Header{
				"Missing": []string{"This is a random header"},
			},
			err: auth.ErrNoAuthHeaderIncluded,
		},
		{
			name: "failure when empty token in 'Authorization' header",
			input: http.Header{
				"Authorization": []string{"ApiKey"},
			},
			err: malformedError,
		},
		{
			name: "failure when 'Authorization' header format is incorrect",
			input: http.Header{
				"Authorization": []string{"NotApiKey this-is-wrong"},
			},
			err: malformedError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.FailNow() // Testing ci workflow

			output, err := auth.GetAPIKey(tt.input)
			if tt.output != output {
				t.FailNow()
			}

			if (tt.err == nil && err != nil) || (tt.err != nil && err == nil) {
				t.FailNow()
			}

			if tt.err != nil && tt.err.Error() != err.Error() {
				t.FailNow()
			}
		})
	}
}

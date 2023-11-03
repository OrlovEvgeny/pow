package hashcash

import (
	"fmt"
	"github.com/stretchr/testify/assert"
	"testing"
	"time"
)

func TestCompute(t *testing.T) {
	mustParse := func(layout, value string) time.Time {
		t, _ := time.Parse(layout, value)
		return t
	}

	type args struct {
		maxAttempts int
		segments    hashSegments
	}

	tests := []struct {
		name    string
		args    args
		want    string
		wantErr assert.ErrorAssertionFunc
	}{
		{
			name: "127.0.0.1",
			args: args{
				maxAttempts: 1000,
				segments: hashSegments{
					version:   1,
					bits:      2,
					issuedAt:  mustParse(defaultDatetimeLayout, "231103022237"),
					expiredAt: mustParse(defaultDatetimeLayout, "321103022237"),
					resource:  "127.0.0.1",
					algo:      SHA256.String(),
					nonce:     "ZG27RRvTK",
				},
			},
			want:    "1:2:231103022237:321103022237:127.0.0.1:SHA-256:ZG27RRvTK:u/t58m9ElIkm6F6CuUOcBWlGpL7FJF3mcjGvyYsGU7Q=:AAAAAA==",
			wantErr: assert.NoError,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Compute(tt.args.maxAttempts, tt.args.segments.sign("private-key"))
			tt.wantErr(t, err)
			assert.Equal(t, tt.want, got)

		})
	}
}

func TestVerify(t *testing.T) {
	type args struct {
		privateKey string
		stamp      string
	}
	tests := []struct {
		name    string
		args    args
		wantErr assert.ErrorAssertionFunc
	}{
		{
			name: "127.0.0.1",
			args: args{
				privateKey: "private-key",
				stamp:      "1:2:231103022237:321103022237:127.0.0.1:SHA-256:ZG27RRvTK:u/t58m9ElIkm6F6CuUOcBWlGpL7FJF3mcjGvyYsGU7Q=:AAAAAA==",
			},
			wantErr: assert.NoError,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := Verify(tt.args.privateKey, tt.args.stamp)
			if !tt.wantErr(t, err, fmt.Sprintf("Verify(%v, %v)", tt.args.privateKey, tt.args.stamp)) {
				return
			}
		})
	}
}

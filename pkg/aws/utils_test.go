package aws

import (
	"testing"

	"github.com/aws/aws-sdk-go/aws"
)

func TestContains(t *testing.T) {
	type args struct {
		a []string
		x string
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{
			name: "#1",
			args: args{a: []string{"a", "b", "c"}, x: "c"},
			want: true,
		},
		{
			name: "#2",
			args: args{a: []string{"a", "b", "c"}, x: "d"},
			want: false,
		},
		{
			name: "#3",
			args: args{a: []string{}, x: "d"},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Contains(tt.args.a, tt.args.x); got != tt.want {
				t.Errorf("Contains() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestAwsStringContains(t *testing.T) {
	type args struct {
		a []*string
		x *string
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{
			name: "#1",
			args: args{a: []*string{aws.String("a"), aws.String("b"), aws.String("c")}, x: aws.String("c")},
			want: true,
		},
		{
			name: "#2",
			args: args{a: []*string{aws.String("a"), aws.String("b"), aws.String("c")}, x: aws.String("d")},
			want: false,
		},
		{
			name: "#3",
			args: args{a: []*string{}, x: aws.String("d")},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := SdkStringContains(tt.args.a, tt.args.x); got != tt.want {
				t.Errorf("SdkStringContains() = %v, want %v", got, tt.want)
			}
		})
	}
}

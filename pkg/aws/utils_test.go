package aws

import (
	"testing"
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

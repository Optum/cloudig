package cloudig

import (
	"testing"

	"github.com/stretchr/testify/assert"
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

func TestMin(t *testing.T) {
	output := min(1, 2)
	assert.Equal(t, 1, output)
	output = min(1, 1)
	assert.Equal(t, 1, output)
	output = min(1, 0)
	assert.Equal(t, 0, output)
}

func TestContainsKey(t *testing.T) {
	type args struct {
		sm  []map[string]string
		key string
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			"#1",
			args{[]map[string]string{
				{"k1": "v1", "k2": "v2", "k3": "v3"},
				{"kk1": "vv1", "kk2": "vv2"},
				{"a1": "v1"},
			},
				"kk2"},
			"vv2",
		},
		{
			"#2",
			args{[]map[string]string{
				{"k1": "v1", "k2": "v2", "k3": "v3"},
				{"kk1": "vv1", "kk2": "vv2"},
				{"a1": "v1"},
			},
				"kk3"},
			"NEW_FINDING",
		},
		{
			"#3",
			args{[]map[string]string{},
				"a1"},
			"NEW_FINDING",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ContainsKey(tt.args.sm, tt.args.key); got != tt.want {
				t.Errorf("ContainsKey() = %v, want %v", got, tt.want)
			}
		})
	}
}

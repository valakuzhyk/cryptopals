package utils

import (
	"reflect"
	"testing"
)

func TestParseKeyValuePairs(t *testing.T) {
	type args struct {
		kvPairs string
	}
	tests := []struct {
		name    string
		args    args
		want    map[string]string
		wantErr bool
	}{
		{"Basic", args{"foo=bar&baz=qux&zap=zazzle"}, map[string]string{"foo": "bar", "baz": "qux", "zap": "zazzle"}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseKeyValuePairs(tt.args.kvPairs)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseKeyValuePairs() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ParseKeyValuePairs() = %v, want %v", got, tt.want)
			}
		})
	}
}

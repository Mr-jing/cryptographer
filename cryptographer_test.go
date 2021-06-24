package cryptographer

import (
	"testing"
)

func Test_crypto_Encrypt(t *testing.T) {
	type fields struct {
		key string
	}
	type args struct {
		plainText []byte
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    string
		wantErr bool
	}{
		//{
		//	name:    "invalid key size",
		//	fields:  fields{key: "invalid key size ",  },
		//	args:    args{plainText: []byte("test")},
		//	want:    "",
		//	wantErr: true,
		//},
		{
			name:    "ok",
			fields:  fields{key: "0123456789123456"},
			args:    args{plainText: []byte("test")},
			want:    "",
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, _ := NewCryptographer(tt.fields.key)
			got, err := c.Encrypt(tt.args.plainText)
			if (err != nil) != tt.wantErr {
				t.Errorf("Encrypt() error = %+v, wantErr %v", err, tt.wantErr)
				return
			}
			if (tt.wantErr && got != tt.want) ||
				(!tt.wantErr && len(got) <= 0) {
				t.Errorf("Encrypt() got = %#v, want %#v", got, tt.want)
			}
		})
	}
}

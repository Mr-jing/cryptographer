package cryptographer

import (
	"crypto/aes"
	"crypto/sha512"
	"reflect"
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

func TestCrypto_Decrypt(t *testing.T) {
	type fields struct {
		key string
	}
	type args struct {
		cipherText string
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    string
		wantErr bool
	}{
		{
			name:    "cipherText too short",
			fields:  fields{key: "0123456789123456"},
			args:    args{cipherText: ""},
			want:    "",
			wantErr: true,
		},
		{
			name:    "normal",
			fields:  fields{key: "0123456789123456"},
			args:    args{cipherText: "fthyLQLIV5yuFWG8mQMdSPsmg6eC904nmAAtKjM5jZ4SMPTMrPAsKKqpBx7MVmiXlOVBz0dX1WjB+Vi/+v7bXVuRPRP1R8hCfKqwg2wHTaO/XgE9"},
			want:    "test",
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, _ := NewCryptographer(tt.fields.key)
			got, err := c.Decrypt(tt.args.cipherText)
			if (err != nil) != tt.wantErr {
				t.Errorf("Decrypt() error = %+v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("Decrypt() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestNewCryptographer(t *testing.T) {
	type args struct {
		key string
	}
	block, _ := aes.NewCipher([]byte("0123456789123456"))
	tests := []struct {
		name    string
		args    args
		want    Cryptographer
		wantErr bool
	}{
		{
			name:    "invalid key size",
			args:    args{key: "invalid key size "},
			want:    nil,
			wantErr: true,
		},
		{
			name: "normal",
			args: args{key: "0123456789123456"},
			want: &Crypto{
				key:     "0123456789123456",
				macHash: sha512.New,
				macSize: sha512.Size,
				block:   block,
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NewCryptographer(tt.args.key)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewCryptographer() error = %+v, wantErr %v", err, tt.wantErr)
				return
			}
			if !(reflect.TypeOf(got) == reflect.TypeOf(tt.want)) {
				t.Errorf("NewCryptographer() got = %#v, want %#v", got, tt.want)
			}
		})
	}
}

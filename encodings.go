package security

import "encoding/base64"

// EncodeBS encodes a byte slice to a base64 string
func EncodeBS(data []byte) string {
	return base64.StdEncoding.EncodeToString(data)
}

// DecodeSB decodes a base64 string to a byte slice
func DecodeSB(data string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(data)
}

// EncodeSS encodes a string to a base64 string
func EncodeSS(data string) string {
	return EncodeBS([]byte(data))
}

// DecodeSS decodes a base64 string to a string
func DecodeSS(data string) (string, error) {
	bytes, err := DecodeSB(data)
	return string(bytes), err
}

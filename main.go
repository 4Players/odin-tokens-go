package odin_tokens

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

type KeyPair struct {
	PublicKey ed25519.PublicKey
	SecretKey ed25519.PrivateKey
}

// GenerateAccessKey generates a new ODIN access key.
func GenerateAccessKey() (string, error) {
	key := make([]byte, 33)
	// version
	key[0] = 0x01
	// seed
	_, err := rand.Read(key[1:32])
	if err != nil {
		return "", err
	}
	// checksum
	key[32] = crc8(key[1:32])
	return base64.StdEncoding.EncodeToString(key), nil
}

// LoadAccessKey validates and loads a key pair from an ODIN access key.
func LoadAccessKey(accessKey string) (KeyPair, error) {
	bytes, err := base64.StdEncoding.DecodeString(accessKey)
	if err != nil || bytes[0] != 0x01 || len(bytes) != 33 || crc8(bytes[1:32]) != bytes[32] {
		return KeyPair{}, errors.New("invalid access key")
	}

	// Generate key pair from seed
	seed := bytes[1:33]
	privateKey := ed25519.NewKeyFromSeed(seed)
	publicKey := privateKey.Public().(ed25519.PublicKey)

	return KeyPair{PublicKey: publicKey, SecretKey: privateKey}, nil
}

// GetKeyId generates a key ID from a given public key.
func GetKeyId(publicKey ed25519.PublicKey) string {
	hash := sha512.Sum512(publicKey)
	result := make([]byte, 9)
	result[0] = 0x01
	for i := 0; i < 8; i++ {
		for j := 0; j < 8; j++ {
			result[1+j] ^= hash[i*8+j]
		}
	}
	return base64.StdEncoding.EncodeToString(result)
}

type TokenOptions struct {
	Customer string
	Audience string
	Subject  string
	Lifetime int
}

// TokenGenerator generates tokens for ODIN network access.
type TokenGenerator struct {
	KeyId     string
	SecretKey ed25519.PrivateKey
}

// NewTokenGenerator creates a TokenGenerator from either an access key or key pair.
func NewTokenGenerator(credentials interface{}) (*TokenGenerator, error) {
	var keyPair KeyPair
	var err error

	switch cred := credentials.(type) {
	case string:
		keyPair, err = LoadAccessKey(cred)
	case KeyPair:
		keyPair = cred
	default:
		return nil, errors.New("invalid credentials type")
	}

	if err != nil {
		return nil, err
	}

	return &TokenGenerator{
		KeyId:     GetKeyId(keyPair.PublicKey),
		SecretKey: keyPair.SecretKey,
	}, nil
}

// CreateToken creates a signed JWT token to access the ODIN room.
func (tg *TokenGenerator) CreateToken(roomId string, userId string, options TokenOptions) (string, error) {
	nbf := time.Now().Unix()
	exp := nbf + int64(options.Lifetime)
	claims := map[string]interface{}{
		"rid": roomId,
		"uid": userId,
		"cid": options.Customer,
		"sub": options.Subject,
		"aud": options.Audience,
		"exp": exp,
		"nbf": nbf,
	}

	for claim := range claims {
		if claims[claim] == "" {
			delete(claims, claim)
		}
	}

	header := map[string]interface{}{
		"alg": "EdDSA",
		"kid": tg.KeyId,
	}

	headerStr, err := base64EncodeObject(header)
	if err != nil {
		return "", err
	}
	claimsStr, err := base64EncodeObject(claims)
	if err != nil {
		return "", err
	}

	body := fmt.Sprintf("%s.%s", headerStr, claimsStr)
	message := []byte(body)
	signature := ed25519.Sign(tg.SecretKey, message)
	return fmt.Sprintf("%s.%s", body, base64.RawURLEncoding.EncodeToString(signature)), nil
}

// crc8 computes the 8-bit Cyclic Redundancy Check (CRC-8) for a given data array.
func crc8(data []byte) byte {
	crc := byte(0xff)
	for _, b := range data {
		crc ^= b
		for i := 0; i < 8; i++ {
			if crc&0x80 != 0 {
				crc = (crc << 1) ^ 0x31
			} else {
				crc <<= 1
			}
		}
	}
	return crc
}

// base64EncodeObject converts an object into a Base64-encoded string representation.
func base64EncodeObject(object interface{}) (string, error) {
	jsonData, err := json.Marshal(object)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(jsonData), nil
}

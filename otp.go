package wallsotplib

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"fmt"
	"time"
)

type OTPGenerator interface {
	GenerateOTP(secretKey string, input string, expiry time.Duration) (string, error)
	ValidateOTP(secretKey string, input string, otp string) (bool, error)
}

type Storage interface {
	SaveOTP(otp string, expiry time.Duration) error
	RetrieveOTP(otp string) (time.Duration, error)
	MarkOTPUsed(otp string) error
}

type HMACOTPGenerator struct {
	storage Storage
}

func NewHMACOTPGenerator(storage Storage) *HMACOTPGenerator {
    if storage == nil {
        // Use the default in-memory storage implementation
        storage = NewMemoryStorage()
    }

    return &HMACOTPGenerator{storage: storage}
}

func (gen *HMACOTPGenerator) GenerateOTP(secretKey string, input string, expiry time.Duration) (string, error) {
	timeStep := time.Now().Unix() / int64(expiry.Seconds())
	key, err := base64.StdEncoding.DecodeString(secretKey)
	if err != nil {
		fmt.Printf("decoding secret key error %v\n", err)
		return "", err
	}
	info := input + string(key)
	otp := generateHOTP(info, timeStep)
	err = gen.storage.SaveOTP(otp, expiry)
	if err != nil {
		return "", err
	}
	return otp, nil
}

func (gen *HMACOTPGenerator) ValidateOTP(secretKey string, input string, otp string) (bool, error) {
	expiry, err := gen.storage.RetrieveOTP(otp)
	if err != nil {
		return false, err
	}
	timeStep := time.Now().Unix() / int64(expiry.Seconds())
	key, err := base64.StdEncoding.DecodeString(secretKey)
	if err != nil {
		fmt.Printf("decoding secret key error %v\n", err)
		return false, err
	}
	info := input + string(key)
	validOtp := generateHOTP(info, timeStep)
	if otp != validOtp {
		return false, fmt.Errorf("invalid OTP")
	}
	err = gen.storage.MarkOTPUsed(otp)
	if err != nil {
		return false, err
	}
	return true, nil
}

func generateHOTP(info string, counter int64) string {
	counterBytes := []byte{
		byte(counter >> 56),
		byte(counter >> 48),
		byte(counter >> 40),
		byte(counter >> 32),
		byte(counter >> 24),
		byte(counter >> 16),
		byte(counter >> 8),
		byte(counter),
	}
	hash := hmac.New(sha1.New, []byte(info))
	hash.Write(counterBytes)
	sum := hash.Sum(nil)
	offset := sum[len(sum)-1] & 0xf
	code := int32((int32(sum[offset])&0x7f)<<24 |
		(int32(sum[offset+1]&0xff) << 16) |
		(int32(sum[offset+2]&0xff) << 8) |
		(int32(sum[offset+3] & 0xff)))
	return fmt.Sprintf("%06d", code%1000000)
}

type MemoryStorage struct {
	otps map[string]time.Duration
}

func NewMemoryStorage() *MemoryStorage {
	return &MemoryStorage{otps: make(map[string]time.Duration)}
}

func (s *MemoryStorage) SaveOTP(otp string, expiry time.Duration) error {
	s.otps[otp] = expiry
	return nil
}

func (s *MemoryStorage) RetrieveOTP(otp string) (time.Duration, error) {
	expiry, exists := s.otps[otp]
	if !exists {
		return 0, fmt.Errorf("OTP not found")
	}
	return expiry, nil
}

func (s *MemoryStorage) MarkOTPUsed(otp string) error {
	delete(s.otps, otp)
	return nil
}
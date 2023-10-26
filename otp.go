package wallsotplib

import (
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"fmt"
	"time"
)

type OTPGenerator interface {
	GenerateOTP(ctx context.Context, createOtpDto CreateOtpDto) (string, error)
    ValidateOTP(ctx context.Context, createOtpDto ValidateOtpDto) (bool, error)
}

type Storage interface {
	SaveOTP(ctx context.Context, otp string, expiry time.Duration) error
	RetrieveOTP(ctx context.Context, otp string) (time.Duration, error)
	MarkOTPUsed(ctx context.Context, otp string) error
}

type HMACOTPGenerator struct {
	storage Storage
	secretKey string
	expiry time.Duration
}

func NewHMACOTPGenerator(storage Storage, secretKey string, expiry time.Duration) *HMACOTPGenerator {
    if storage == nil {
        // Use the default in-memory storage implementation
        storage = NewMemoryStorage()
    }

    return &HMACOTPGenerator{storage: storage,
							secretKey: secretKey,
							expiry: expiry,
	}
}

func (gen *HMACOTPGenerator) GenerateOTP(ctx context.Context, createOtpDto CreateOtpDto) (string, error) {
	timeStep := time.Now().Unix() / int64(gen.expiry.Seconds())
	key, err := base64.StdEncoding.DecodeString(gen.secretKey)
	if err != nil {
		fmt.Printf("decoding secret key error %v\n", err)
		return "", err
	}
	input:= createOtpDto.Contact + ":" + createOtpDto.DeviceImei + ":" + createOtpDto.OtpType 
	info := input + string(key)
	otp := generateHOTP(info, timeStep)
	err = gen.storage.SaveOTP(ctx,otp, gen.expiry)
	if err != nil {
		return "", err
	}
	return otp, nil
}

func (gen *HMACOTPGenerator) ValidateOTP(ctx context.Context, validateOtpDto ValidateOtpDto) (bool, error) {
	expiry, err := gen.storage.RetrieveOTP(ctx,validateOtpDto.Otp)
	if err != nil {
		return false, err
	}
	timeStep := time.Now().Unix() / int64(expiry.Seconds())
	key, err := base64.StdEncoding.DecodeString(gen.secretKey)
	if err != nil {
		fmt.Printf("decoding secret key error %v\n", err)
		return false, err
	}
	input:= validateOtpDto.Contact + ":" + validateOtpDto.DeviceImei + ":" + validateOtpDto.OtpType 
	info := input + string(key)
	validOtp := generateHOTP(info, timeStep)
	if validateOtpDto.Otp != validOtp {
		return false, fmt.Errorf("invalid OTP")
	}
	err = gen.storage.MarkOTPUsed(ctx,validateOtpDto.Otp)
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

func (s *MemoryStorage) SaveOTP(ctx context.Context,otp string, expiry time.Duration) error {
	s.otps[otp] = expiry
	return nil
}

func (s *MemoryStorage) RetrieveOTP(ctx context.Context,otp string) (time.Duration, error) {
	expiry, exists := s.otps[otp]
	if !exists {
		return 0, fmt.Errorf("OTP not found")
	}
	return expiry, nil
}

func (s *MemoryStorage) MarkOTPUsed(ctx context.Context,otp string) error {
	delete(s.otps, otp)
	return nil
}
type CreateOtpDto struct {
	OtpType string    `json:"otp_type" bson:"otp_type" validate:"required,eq=create_user|eq=create_company|eq=verify_email|eq=verify_phone"`
	Contact string    `json:"contact" bson:"contact" validate:"required,valid_contact"`
	Channel string    `json:"channel" bson:"channel" validate:"eq=sms|eq=email|eq=in_app"`
	DeviceImei             string `json:"imei" bson:"imei" validate:"required,imei,min=10,max=50"`
	Duration     time.Duration    `json:"duration" bson:"duration"`
	Timestamp    string `json:"timestamp" bson:"timestamp"`
}

type ValidateOtpDto struct {
	Otp     string    `json:"otp" bson:"otp" validate:"required,len=6"`
	OtpType string    `json:"otp_type" bson:"otp_type" validate:"required,eq=create_user|eq=create_company|eq=verify_email"`
	Contact string    `json:"contact" bson:"contact" validate:"valid_contact"`
	DeviceImei              string `json:"imei" bson:"imei" validate:"required,imei,min=10,max=50"`
	Duration     time.Duration    `json:"duration" bson:"duration"`
}
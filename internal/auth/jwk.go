package auth

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"fmt"
	"math/big"
)

// parseRSAPublicKey builds an *rsa.PublicKey from base64url-encoded JWK
// modulus/exponent values, rejecting keys too small to be meaningful.
func parseRSAPublicKey(nB64, eB64 string) (*rsa.PublicKey, error) {
	nBytes, err := base64.RawURLEncoding.DecodeString(nB64)
	if err != nil {
		return nil, fmt.Errorf("decode RSA modulus: %w", err)
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(eB64)
	if err != nil {
		return nil, fmt.Errorf("decode RSA exponent: %w", err)
	}
	if len(nBytes) < 256 { // < 2048 bits
		return nil, fmt.Errorf("RSA modulus too small (%d bytes)", len(nBytes))
	}
	n := new(big.Int).SetBytes(nBytes)
	e := new(big.Int).SetBytes(eBytes)
	if !e.IsInt64() || e.Int64() < 2 {
		return nil, fmt.Errorf("invalid RSA exponent")
	}
	return &rsa.PublicKey{N: n, E: int(e.Int64())}, nil
}

// parseECDSAPublicKey builds an *ecdsa.PublicKey from a JWK EC key, verifying
// that the point lies on the named curve.
func parseECDSAPublicKey(crv, xB64, yB64 string) (*ecdsa.PublicKey, error) {
	var ecdhCurve ecdh.Curve
	var ellCurve elliptic.Curve
	switch crv {
	case "P-256":
		ecdhCurve, ellCurve = ecdh.P256(), elliptic.P256()
	case "P-384":
		ecdhCurve, ellCurve = ecdh.P384(), elliptic.P384()
	case "P-521":
		ecdhCurve, ellCurve = ecdh.P521(), elliptic.P521()
	default:
		return nil, fmt.Errorf("unsupported EC curve %q", crv)
	}
	xBytes, err := base64.RawURLEncoding.DecodeString(xB64)
	if err != nil {
		return nil, fmt.Errorf("decode EC x: %w", err)
	}
	yBytes, err := base64.RawURLEncoding.DecodeString(yB64)
	if err != nil {
		return nil, fmt.Errorf("decode EC y: %w", err)
	}
	// ecdh.Curve.NewPublicKey expects the SEC 1 uncompressed point encoding
	// (0x04 || X || Y, each coordinate zero-padded to the curve's byte size)
	// and rejects points that are not on the curve.
	size := (ellCurve.Params().BitSize + 7) / 8
	if len(xBytes) > size || len(yBytes) > size {
		return nil, fmt.Errorf("EC coordinate too large for curve %q", crv)
	}
	point := make([]byte, 1+2*size)
	point[0] = 4
	copy(point[1+size-len(xBytes):], xBytes)
	copy(point[1+2*size-len(yBytes):], yBytes)
	if _, err := ecdhCurve.NewPublicKey(point); err != nil {
		return nil, fmt.Errorf("EC point not on curve %q", crv)
	}
	x := new(big.Int).SetBytes(xBytes)
	y := new(big.Int).SetBytes(yBytes)
	return &ecdsa.PublicKey{Curve: ellCurve, X: x, Y: y}, nil
}

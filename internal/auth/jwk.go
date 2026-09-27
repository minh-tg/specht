package auth

import (
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
	var ellCurve elliptic.Curve
	switch crv {
	case "P-256":
		ellCurve = elliptic.P256()
	case "P-384":
		ellCurve = elliptic.P384()
	case "P-521":
		ellCurve = elliptic.P521()
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
	key, err := ecdsa.ParseUncompressedPublicKey(ellCurve, point)
	if err != nil {
		return nil, fmt.Errorf("EC point not on curve %q: %w", crv, err)
	}
	return key, nil
}

// Tom Curves
package tom

import (
	"encoding/asn1"
	"crypto/ecdsa"
	"crypto/elliptic"
	"math/big"
	"sync"
	"errors"
)

var (
	oidTom = asn1.ObjectIdentifier{1, 2, 999, 1, 1, 1}

	oidTom256 = asn1.ObjectIdentifier{1, 2, 999, 1, 1, 1, 1}
	oidTom384 = asn1.ObjectIdentifier{1, 2, 999, 1, 1, 1, 2}
	oidTom521 = asn1.ObjectIdentifier{1, 2, 999, 1, 1, 1, 3}
)

var p256 *elliptic.CurveParams
var p384 *elliptic.CurveParams
var p521 *elliptic.CurveParams

// sync.Once variable to ensure initialization occurs only once
var initonce sync.Once

// Initialization of curve P256
func init() {
	initP256()
	initP384()
	initP521()
}

// Function to initialize curve P256
func initP256() {
	p256 = new(elliptic.CurveParams)
	p256.P, _ = new(big.Int).SetString("ffffffff0000000100000000000000017e72b42b30e7317793135661b1c4b117", 16)
	p256.N, _ = new(big.Int).SetString("ffffffff00000001000000000000000000000000ffffffffffffffffffffffff", 16)
	p256.B, _ = new(big.Int).SetString("b441071b12f4a0366fb552f8e21ed4ac36b06aceeb354224863e60f20219fc56", 16)
	p256.Gx, _ = new(big.Int).SetString("03", 16)
	p256.Gy, _ = new(big.Int).SetString("5a6dd32df58708e64e97345cbe66600decd9d538a351bb3c30b4954925b1f02d", 16)
	p256.BitSize = 256
	p256.Name = "Tom-256"
}

// Function to return the P256 curve, using the initialization done in init
func P256() elliptic.Curve {
	initonce.Do(initP256)
	return p256
}

// Function to initialize curve P384
func initP384() {
	p384 = new(elliptic.CurveParams)
	p384.P, _ = new(big.Int).SetString("fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff", 16)
	p384.N, _ = new(big.Int).SetString("ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973", 16)
	p384.B, _ = new(big.Int).SetString("b3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aef", 16)
	p384.Gx, _ = new(big.Int).SetString("aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7", 16)
	p384.Gy, _ = new(big.Int).SetString("3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f", 16)
	p384.Name = "Tom-384"
	p384.BitSize = 384
}

// Function to return the P384 curve, using the initialization done in init
func P384() elliptic.Curve {
	initonce.Do(initP384)
	return p384
}

// Function to initialize curve P384
func initP521() {
	p521 = new(elliptic.CurveParams)
	p521.P, _ = new(big.Int).SetString("200000000000000000000000000000000000000000000000000000000000000002c54be78524c33584f734a266748b2063accf5028e6778dc5056476d0690853249", 16)
	p521.N, _ = new(big.Int).SetString("01ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", 16)
	p521.B, _ = new(big.Int).SetString("3cbc65d1e0245d79703b18e9aaea1ac6d67f87a2cd4bd84b9e6df6a45a979c481825ca5a857270fc890352f9fac7fd6020deaabb28d099718f0f77a4eec222871d", 16)
	p521.Gx, _ = new(big.Int).SetString("01", 16)
	p521.Gy, _ = new(big.Int).SetString("460445824ae9715345c16334b3280c75ded69c90b8417b75fc1f88e1e09fa1c179b3cff0f2f4297f0530ef6ed6ae605ee7a575ef72575b1282fd1fb8b00120ba01", 16)
	p521.Name = "Tom-521"
	p384.BitSize = 521
}

// Function to return the P384 curve, using the initialization done in init
func P521() elliptic.Curve {
	initonce.Do(initP521)
	return p521
}

// Structures to represent public and private keys
type PublicKey struct {
	X, Y  *big.Int
	Curve elliptic.Curve
}

type PrivateKey struct {
	PublicKey PublicKey
	D         *big.Int
}

// Function to convert the public key to ECDSA
func (pk *PublicKey) ToECDSA() *ecdsa.PublicKey {
	return &ecdsa.PublicKey{
		Curve: pk.Curve,
		X:     pk.X,
		Y:     pk.Y,
	}
}

// Function to convert the private key to ECDSA
func (pk *PrivateKey) ToECDSAPrivateKey() *ecdsa.PrivateKey {
	return &ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{
			Curve: pk.PublicKey.Curve,
			X:     pk.PublicKey.X,
			Y:     pk.PublicKey.Y,
		},
		D: pk.D,
	}
}

// Function to create a new private key from an ECDSA private key
func NewPrivateKey(privateKey *ecdsa.PrivateKey) *PrivateKey {
	return &PrivateKey{
		PublicKey: PublicKey{
			Curve: privateKey.PublicKey.Curve,
			X:     privateKey.PublicKey.X,
			Y:     privateKey.PublicKey.Y,
		},
		D: privateKey.D,
	}
}

func ECDH(privateKey *ecdsa.PrivateKey, publicKey *ecdsa.PublicKey) ([]byte, error) {
	// Compute shared key
	x, _ := privateKey.Curve.ScalarMult(publicKey.X, publicKey.Y, privateKey.D.Bytes())
	return x.Bytes(), nil
}

// Define pkAlgorithmIdentifier to avoid undefined identifier
type pkAlgorithmIdentifier struct {
	Algorithm  asn1.ObjectIdentifier
	Parameters asn1.RawValue
}

func (pk *PublicKey) MarshalPKCS8PublicKey(curve elliptic.Curve) ([]byte, error) {
	// Marshal the public key coordinates
	derBytes := elliptic.Marshal(curve, pk.X, pk.Y)

	// Determine the OID based on the curve
	var oid asn1.ObjectIdentifier
	switch curve {
	case P256():
		oid = oidTom256
	case P384():
		oid = oidTom384
	case P521():
		oid = oidTom521
	default:
		return nil, errors.New("unsupported curve")
	}

	// Create a SubjectPublicKeyInfo structure
	subjectPublicKeyInfo := struct {
		Algorithm pkAlgorithmIdentifier
		PublicKey asn1.BitString
	}{
		Algorithm: pkAlgorithmIdentifier{
			Algorithm:  oid,
			Parameters: asn1.RawValue{Tag: asn1.TagOID, Bytes: []byte(oid.String())},
		},
		PublicKey: asn1.BitString{Bytes: derBytes, BitLength: len(derBytes) * 8},
	}

	// Marshal the SubjectPublicKeyInfo structure
	derBytes, err := asn1.Marshal(subjectPublicKeyInfo)
	if err != nil {
		return nil, err
	}

	return derBytes, nil
}

func ParsePublicKey(der []byte) (*PublicKey, error) {
	var publicKeyInfo struct {
		Algorithm pkAlgorithmIdentifier
		PublicKey asn1.BitString
	}

	_, err := asn1.Unmarshal(der, &publicKeyInfo)
	if err != nil {
		return nil, err
	}

	var curve elliptic.Curve
	switch {
	case publicKeyInfo.Algorithm.Algorithm.Equal(oidTom256):
		curve = P256()
	case publicKeyInfo.Algorithm.Algorithm.Equal(oidTom384):
		curve = P384()
	case publicKeyInfo.Algorithm.Algorithm.Equal(oidTom521):
		curve = P521()
	default:
		return nil, errors.New("unsupported curve OID")
	}

	// Check if the public key bytes are empty
	if len(publicKeyInfo.PublicKey.Bytes) == 0 {
		return nil, errors.New("public key bytes are empty")
	}

	// Unmarshal the public key coordinates
	X, Y := elliptic.Unmarshal(curve, publicKeyInfo.PublicKey.Bytes)
	if X == nil || Y == nil {
		return nil, errors.New("failed to unmarshal public key")
	}

	// Return the parsed public key with the determined curve
	return &PublicKey{X: X, Y: Y, Curve: curve}, nil
}

func (pk *PrivateKey) MarshalPKCS8PrivateKey(curve elliptic.Curve) ([]byte, error) {
	if !curve.IsOnCurve(pk.PublicKey.X, pk.PublicKey.Y) {
		return nil, errors.New("Public key is not on the curve")
	}

	// Convert the private key D to bytes
	dBytes := pk.D.Bytes()

	curveSize := (curve.Params().BitSize + 7) / 8
	if len(dBytes) < curveSize {
		padding := make([]byte, curveSize-len(dBytes))
		dBytes = append(padding, dBytes...)
	}

	// Determine the OID based on the curve
	var oid asn1.ObjectIdentifier
	switch curve {
	case P256():
		oid = oidTom256
	case P384():
		oid = oidTom384
	case P521():
		oid = oidTom521
	default:
		return nil, errors.New("unsupported curve")
	}

	// Create a PrivateKeyInfo structure
	privateKeyInfo := struct {
		Version             int
		PrivateKeyAlgorithm pkAlgorithmIdentifier
		PublicKey           struct {
			X *big.Int
			Y *big.Int
		}
		PrivateKey []byte
	}{
		Version: 0,
		PrivateKeyAlgorithm: pkAlgorithmIdentifier{
			Algorithm:  oid,
			Parameters: asn1.RawValue{Tag: asn1.TagOID, Bytes: []byte(oid.String())},
		},
		PublicKey: struct {
			X *big.Int
			Y *big.Int
		}{
			X: new(big.Int).SetBytes(pk.PublicKey.X.Bytes()),
			Y: new(big.Int).SetBytes(pk.PublicKey.Y.Bytes()),
		},
		PrivateKey: dBytes,
	}

	// Marshal the PrivateKeyInfo structure
	derBytes, err := asn1.Marshal(privateKeyInfo)
	if err != nil {
		return nil, err
	}

	return derBytes, nil
}

func ParsePrivateKey(der []byte) (*PrivateKey, error) {
	var privateKeyInfo struct {
		Version             int
		PrivateKeyAlgorithm pkAlgorithmIdentifier
		PublicKey           struct {
			X *big.Int
			Y *big.Int
		}
		PrivateKey []byte
	}
	_, err := asn1.Unmarshal(der, &privateKeyInfo)
	if err != nil {
		return nil, err
	}

	// Determine the curve based on the OID
	var curve elliptic.Curve
	switch {
	case privateKeyInfo.PrivateKeyAlgorithm.Algorithm.Equal(oidTom256):
		curve = P256()
	case privateKeyInfo.PrivateKeyAlgorithm.Algorithm.Equal(oidTom384):
		curve = P384()
	case privateKeyInfo.PrivateKeyAlgorithm.Algorithm.Equal(oidTom521):
		curve = P521()
	default:
		return nil, errors.New("unsupported curve OID")
	}

	X := privateKeyInfo.PublicKey.X
	Y := privateKeyInfo.PublicKey.Y
	D := new(big.Int).SetBytes(privateKeyInfo.PrivateKey)

	if !curve.IsOnCurve(X, Y) {
		return nil, errors.New("Public key is not on the curve")
	}

	// Create and return the private key with the determined curve
	privateKey := &PrivateKey{
		PublicKey: PublicKey{
			X:     X,
			Y:     Y,
			Curve: curve,
		},
		D: D,
	}

	return privateKey, nil
}


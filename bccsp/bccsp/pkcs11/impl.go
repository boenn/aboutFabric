/*
Copyright IBM Corp. 2016 All Rights Reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

		 http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package pkcs11

import (
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sm2"
	"crypto/sm3"
	"crypto/x509"
	"errors"
	"fmt"
	"math/big"
	"os"

	"github.com/hyperledger/fabric/bccsp"
	"github.com/hyperledger/fabric/bccsp/sw"
	"github.com/hyperledger/fabric/bccsp/utils"
	"github.com/hyperledger/fabric/common/flogging"
	"github.com/miekg/pkcs11"
)

var (
	logger           = flogging.MustGetLogger("bccsp_p11")
	sessionCacheSize = 10
)

// New returns a new instance of the software-based BCCSP
// set at the passed security level, hash family and KeyStore.
func New(opts PKCS11Opts, keyStore bccsp.KeyStore) (bccsp.BCCSP, error) {
	// Init config
	conf := &config{}
	err := conf.setSecurityLevel(opts.SecLevel, opts.HashFamily)
	if err != nil {
		return nil, fmt.Errorf("Failed initializing configuration [%s]", err)
	}

	swCSP, err := sw.New(opts.SecLevel, opts.HashFamily, keyStore)
	if err != nil {
		return nil, fmt.Errorf("Failed initializing fallback SW BCCSP [%s]", err)
	}

	// Check KeyStore
	if keyStore == nil {
		return nil, errors.New("Invalid bccsp.KeyStore instance. It must be different from nil.")
	}

	lib := opts.Library
	pin := opts.Pin
	label := opts.Label
	ctx, slot, session, err := loadLib(lib, pin, label)
	if err != nil {
		return nil, fmt.Errorf("Failed initializing PKCS11 library %s %s [%s]",
			lib, label, err)
	}

	sessions := make(chan pkcs11.SessionHandle, sessionCacheSize)
	csp := &impl{swCSP, conf, keyStore, ctx, sessions, slot, lib, opts.Sensitive, opts.SoftVerify}
	csp.returnSession(*session)
	return csp, nil
}

type impl struct {
	bccsp.BCCSP

	conf *config
	ks   bccsp.KeyStore

	ctx      *pkcs11.Ctx
	sessions chan pkcs11.SessionHandle
	slot     uint

	lib          string
	noPrivImport bool
	softVerify   bool
}

// KeyGen generates a key using opts.
func (csp *impl) KeyGen(opts bccsp.KeyGenOpts) (k bccsp.Key, err error) {
	// Validate arguments
	if opts == nil {
		return nil, errors.New("Invalid Opts parameter. It must not be nil.")
	}

	// Parse algorithm
	switch opts.(type) {
	case *bccsp.SM2KeyGenOpts:
		ski, pub, err := csp.generateECKey(csp.conf.ellipticCurve, opts.Ephemeral())
		if err != nil {
			return nil, fmt.Errorf("Failed generating SM2 key [%s]", err)
		}
		k = &sm2PrivateKey{ski, sm2PublicKey{ski, pub}}

	case *bccsp.SM2P256_sm2KeyGenOpts:
		ski, pub, err := csp.generateECKey(oidNamedCurveP256_sm2, opts.Ephemeral())
		if err != nil {
			return nil, fmt.Errorf("Failed generating SM2 P256_sm2 key [%s]", err)
		}

		k = &sm2PrivateKey{ski, sm2PublicKey{ski, pub}}

	default:
		return csp.BCCSP.KeyGen(opts)
	}

	return k, nil
}

// KeyDeriv derives a key from k using opts.
// The opts argument should be appropriate for the primitive used.
func (csp *impl) KeyDeriv(k bccsp.Key, opts bccsp.KeyDerivOpts) (dk bccsp.Key, err error) {
	// Validate arguments
	if k == nil {
		return nil, errors.New("Invalid Key. It must not be nil.")
	}

	// Derive key
	switch k.(type) {
	case *sm2PublicKey:
		// Validate opts
		if opts == nil {
			return nil, errors.New("Invalid Opts parameter. It must not be nil.")
		}

		sm2K := k.(*sm2PublicKey)

		switch opts.(type) {

		// Re-randomized an SM2 public key
		case *bccsp.SM2ReRandKeyOpts:
			pubKey := sm2K.pub
			if pubKey == nil {
				return nil, errors.New("Public base key cannot be nil.")
			}
			reRandOpts := opts.(*bccsp.SM2ReRandKeyOpts)
			tempSK := &sm2.PublicKey{
				Curve: pubKey.Curve,
				X:     new(big.Int),
				Y:     new(big.Int),
			}

			var k = new(big.Int).SetBytes(reRandOpts.ExpansionValue())
			var one = new(big.Int).SetInt64(1)
			n := new(big.Int).Sub(pubKey.Params().N, one)
			k.Mod(k, n)
			k.Add(k, one)

			// Compute temporary public key
			tempX, tempY := pubKey.ScalarBaseMult(k.Bytes())
			tempSK.X, tempSK.Y = tempSK.Add(
				pubKey.X, pubKey.Y,
				tempX, tempY,
			)

			// Verify temporary public key is a valid point on the reference curve
			isOn := tempSK.Curve.IsOnCurve(tempSK.X, tempSK.Y)
			if !isOn {
				return nil, errors.New("Failed temporary public key IsOnCurve check.")
			}

			ecPt := elliptic.Marshal(tempSK.Curve, tempSK.X, tempSK.Y)
			oid, ok := oidFromNamedCurve(tempSK.Curve)
			if !ok {
				return nil, errors.New("Do not know OID for this Curve.")
			}

			ski, err := csp.importECKey(oid, nil, ecPt, opts.Ephemeral(), publicKeyFlag)
			if err != nil {
				return nil, fmt.Errorf("Failed getting importing EC Public Key [%s]", err)
			}
			reRandomizedKey := &sm2PublicKey{ski, tempSK}

			return reRandomizedKey, nil

		default:
			return nil, fmt.Errorf("Unrecognized KeyDerivOpts provided [%s]", opts.Algorithm())

		}
	case *sm2PrivateKey:
		// Validate opts
		if opts == nil {
			return nil, errors.New("Invalid Opts parameter. It must not be nil.")
		}

		sm2K := k.(*sm2PrivateKey)

		switch opts.(type) {

		// Re-randomized an SM2 private key
		case *bccsp.SM2ReRandKeyOpts:
			reRandOpts := opts.(*bccsp.SM2ReRandKeyOpts)
			pubKey := sm2K.pub.pub
			if pubKey == nil {
				return nil, errors.New("Public base key cannot be nil.")
			}

			secret := csp.getSecretValue(sm2K.ski)
			if secret == nil {
				return nil, errors.New("Could not obtain EC Private Key")
			}
			bigSecret := new(big.Int).SetBytes(secret)

			tempSK := &sm2.PrivateKey{
				PublicKey: sm2.PublicKey{
					Curve: pubKey.Curve,
					X:     new(big.Int),
					Y:     new(big.Int),
				},
				D: new(big.Int),
			}

			var k = new(big.Int).SetBytes(reRandOpts.ExpansionValue())
			var one = new(big.Int).SetInt64(1)
			n := new(big.Int).Sub(pubKey.Params().N, one)
			k.Mod(k, n)
			k.Add(k, one)

			tempSK.D.Add(bigSecret, k)
			tempSK.D.Mod(tempSK.D, pubKey.Params().N)

			// Compute temporary public key
			tempSK.PublicKey.X, tempSK.PublicKey.Y = pubKey.ScalarBaseMult(tempSK.D.Bytes())

			// Verify temporary public key is a valid point on the reference curve
			isOn := tempSK.Curve.IsOnCurve(tempSK.PublicKey.X, tempSK.PublicKey.Y)
			if !isOn {
				return nil, errors.New("Failed temporary public key IsOnCurve check.")
			}

			ecPt := elliptic.Marshal(tempSK.Curve, tempSK.X, tempSK.Y)
			oid, ok := oidFromNamedCurve(tempSK.Curve)
			if !ok {
				return nil, errors.New("Do not know OID for this Curve.")
			}

			ski, err := csp.importECKey(oid, tempSK.D.Bytes(), ecPt, opts.Ephemeral(), privateKeyFlag)
			if err != nil {
				return nil, fmt.Errorf("Failed getting importing EC Public Key [%s]", err)
			}
			reRandomizedKey := &sm2PrivateKey{ski, sm2PublicKey{ski, &tempSK.PublicKey}}

			return reRandomizedKey, nil

		default:
			return nil, fmt.Errorf("Unrecognized KeyDerivOpts provided [%s]", opts.Algorithm())

		}

	default:
		return csp.BCCSP.KeyDeriv(k, opts)

	}
}

// KeyImport imports a key from its raw representation using opts.
// The opts argument should be appropriate for the primitive used.
func (csp *impl) KeyImport(raw interface{}, opts bccsp.KeyImportOpts) (k bccsp.Key, err error) {
	// Validate arguments
	if raw == nil {
		return nil, errors.New("Invalid raw. Cannot be nil.")
	}

	if opts == nil {
		return nil, errors.New("Invalid Opts parameter. It must not be nil.")
	}

	switch opts.(type) {

	case *bccsp.SM2PKIXPublicKeyImportOpts:
		der, ok := raw.([]byte)
		if !ok {
			return nil, errors.New("[SM2PKIXPublicKeyImportOpts] Invalid raw material. Expected byte array.")
		}

		if len(der) == 0 {
			return nil, errors.New("[SM2PKIXPublicKeyImportOpts] Invalid raw. It must not be nil.")
		}

		lowLevelKey, err := utils.DERToPublicKey(der)
		if err != nil {
			return nil, fmt.Errorf("Failed converting PKIX to SM2 public key [%s]", err)
		}

		sm2PK, ok := lowLevelKey.(*sm2.PublicKey)
		if !ok {
			return nil, errors.New("Failed casting to SM2 public key. Invalid raw material.")
		}

		ecPt := elliptic.Marshal(sm2PK.Curve, sm2PK.X, sm2PK.Y)
		oid, ok := oidFromNamedCurve(sm2PK.Curve)
		if !ok {
			return nil, errors.New("Do not know OID for this Curve.")
		}

		var ski []byte
		if csp.noPrivImport {
			// opencryptoki does not support public ec key imports. This is a sufficient
			// workaround for now to use soft verify
			hash := sm3.Sum(ecPt)
			ski = hash[:]
		} else {
			// Warn about potential future problems
			if !csp.softVerify {
				logger.Debugf("opencryptoki workaround warning: Importing public EC Key does not store out to pkcs11 store,\n" +
					"so verify with this key will fail, unless key is already present in store. Enable 'softwareverify'\n" +
					"in pkcs11 options, if suspect this issue.")
			}
			ski, err = csp.importECKey(oid, nil, ecPt, opts.Ephemeral(), publicKeyFlag)
			if err != nil {
				return nil, fmt.Errorf("Failed getting importing EC Public Key [%s]", err)
			}
		}

		k = &sm2PublicKey{ski, sm2PK}
		return k, nil

	case *bccsp.SM2PrivateKeyImportOpts:
		if csp.noPrivImport {
			return nil, errors.New("[SM2DERPrivateKeyImportOpts] PKCS11 options 'sensitivekeys' is set to true. Cannot import.")
		}

		der, ok := raw.([]byte)
		if !ok {
			return nil, errors.New("[SM2DERPrivateKeyImportOpts] Invalid raw material. Expected byte array.")
		}

		if len(der) == 0 {
			return nil, errors.New("[SM2DERPrivateKeyImportOpts] Invalid raw. It must not be nil.")
		}

		lowLevelKey, err := utils.DERToPrivateKey(der)
		if err != nil {
			return nil, fmt.Errorf("Failed converting PKIX to SM2 public key [%s]", err)
		}

		sm2SK, ok := lowLevelKey.(*sm2.PrivateKey)
		if !ok {
			return nil, errors.New("Failed casting to SM2 public key. Invalid raw material.")
		}

		ecPt := elliptic.Marshal(sm2SK.Curve, sm2SK.X, sm2SK.Y)
		oid, ok := oidFromNamedCurve(sm2SK.Curve)
		if !ok {
			return nil, errors.New("Do not know OID for this Curve.")
		}

		ski, err := csp.importECKey(oid, sm2SK.D.Bytes(), ecPt, opts.Ephemeral(), privateKeyFlag)
		if err != nil {
			return nil, fmt.Errorf("Failed getting importing EC Private Key [%s]", err)
		}

		k = &sm2PrivateKey{ski, sm2PublicKey{ski, &sm2SK.PublicKey}}
		return k, nil

	case *bccsp.SM2GoPublicKeyImportOpts:
		lowLevelKey, ok := raw.(*sm2.PublicKey)
		if !ok {
			return nil, errors.New("[SM2GoPublicKeyImportOpts] Invalid raw material. Expected *sm2.PublicKey.")
		}

		ecPt := elliptic.Marshal(lowLevelKey.Curve, lowLevelKey.X, lowLevelKey.Y)
		oid, ok := oidFromNamedCurve(lowLevelKey.Curve)
		if !ok {
			return nil, errors.New("Do not know OID for this Curve.")
		}

		var ski []byte
		if csp.noPrivImport {
			// opencryptoki does not support public ec key imports. This is a sufficient
			// workaround for now to use soft verify
			hash := sm3.Sum(ecPt)
			ski = hash[:]
		} else {
			// Warn about potential future problems
			if !csp.softVerify {
				logger.Debugf("opencryptoki workaround warning: Importing public EC Key does not store out to pkcs11 store,\n" +
					"so verify with this key will fail, unless key is already present in store. Enable 'softwareverify'\n" +
					"in pkcs11 options, if suspect this issue.")
			}
			ski, err = csp.importECKey(oid, nil, ecPt, opts.Ephemeral(), publicKeyFlag)
			if err != nil {
				return nil, fmt.Errorf("Failed getting importing EC Public Key [%s]", err)
			}
		}

		k = &sm2PublicKey{ski, lowLevelKey}
		return k, nil

	case *bccsp.X509PublicKeyImportOpts:
		x509Cert, ok := raw.(*x509.Certificate)
		if !ok {
			return nil, errors.New("[X509PublicKeyImportOpts] Invalid raw material. Expected *x509.Certificate.")
		}

		pk := x509Cert.PublicKey

		switch pk.(type) {
		case *sm2.PublicKey:
			return csp.KeyImport(pk, &bccsp.SM2GoPublicKeyImportOpts{Temporary: opts.Ephemeral()})
		case *rsa.PublicKey:
			return csp.KeyImport(pk, &bccsp.RSAGoPublicKeyImportOpts{Temporary: opts.Ephemeral()})
		default:
			return nil, errors.New("Certificate's public key type not recognized. Supported keys: [SM2, RSA]")
		}

	default:
		return csp.BCCSP.KeyImport(raw, opts)

	}
}

// GetKey returns the key this CSP associates to
// the Subject Key Identifier ski.
func (csp *impl) GetKey(ski []byte) (k bccsp.Key, err error) {
	pubKey, isPriv, err := csp.getECKey(ski)
	if err == nil {
		if isPriv {
			return &sm2PrivateKey{ski, sm2PublicKey{ski, pubKey}}, nil
		} else {
			return &sm2PublicKey{ski, pubKey}, nil
		}
	}
	return csp.BCCSP.GetKey(ski)
}

// Sign signs digest using key k.
// The opts argument should be appropriate for the primitive used.
//
// Note that when a signature of a hash of a larger message is needed,
// the caller is responsible for hashing the larger message and passing
// the hash (as digest).
func (csp *impl) Sign(k bccsp.Key, digest []byte, opts bccsp.SignerOpts) (signature []byte, err error) {
	// Validate arguments
	if k == nil {
		return nil, errors.New("Invalid Key. It must not be nil.")
	}
	if len(digest) == 0 {
		return nil, errors.New("Invalid digest. Cannot be empty.")
	}

	// Check key type
	switch k.(type) {
	case *sm2PrivateKey:
		return csp.signSM2(*k.(*sm2PrivateKey), digest, opts)
	default:
		return csp.BCCSP.Sign(k, digest, opts)
	}
}

// Verify verifies signature against key k and digest
func (csp *impl) Verify(k bccsp.Key, signature, digest []byte, opts bccsp.SignerOpts) (valid bool, err error) {
	// Validate arguments
	if k == nil {
		return false, errors.New("Invalid Key. It must not be nil.")
	}
	if len(signature) == 0 {
		return false, errors.New("Invalid signature. Cannot be empty.")
	}
	if len(digest) == 0 {
		return false, errors.New("Invalid digest. Cannot be empty.")
	}

	// Check key type
	switch k.(type) {
	case *sm2PrivateKey:
		return csp.verifySM2(k.(*sm2PrivateKey).pub, signature, digest, opts)
	case *sm2PublicKey:
		return csp.verifySM2(*k.(*sm2PublicKey), signature, digest, opts)
	default:
		return csp.BCCSP.Verify(k, signature, digest, opts)
	}
}

// Encrypt encrypts plaintext using key k.
// The opts argument should be appropriate for the primitive used.
func (csp *impl) Encrypt(k bccsp.Key, plaintext []byte, opts bccsp.EncrypterOpts) (ciphertext []byte, err error) {
	// TODO: Add PKCS11 support for encryption, when fabric starts requiring it
	return csp.BCCSP.Encrypt(k, plaintext, opts)
}

// Decrypt decrypts ciphertext using key k.
// The opts argument should be appropriate for the primitive used.
func (csp *impl) Decrypt(k bccsp.Key, ciphertext []byte, opts bccsp.DecrypterOpts) (plaintext []byte, err error) {
	return csp.BCCSP.Decrypt(k, ciphertext, opts)
}

// THIS IS ONLY USED FOR TESTING
// This is a convenience function. Useful to self-configure, for tests where usual configuration is not
// available
func FindPKCS11Lib() (lib, pin, label string) {
	//FIXME: Till we workout the configuration piece, look for the libraries in the familiar places
	lib = os.Getenv("PKCS11_LIB")
	if lib == "" {
		pin = "98765432"
		label = "ForFabric"
		possibilities := []string{
			"/usr/lib/softhsm/libsofthsm2.so",                            //Debian
			"/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so",           //Ubuntu
			"/usr/lib/s390x-linux-gnu/softhsm/libsofthsm2.so",            //Ubuntu
			"/usr/lib/powerpc64le-linux-gnu/softhsm/libsofthsm2.so",      //Power
			"/usr/local/Cellar/softhsm/2.1.0/lib/softhsm/libsofthsm2.so", //MacOS
		}
		for _, path := range possibilities {
			if _, err := os.Stat(path); !os.IsNotExist(err) {
				lib = path
				break
			}
		}
	} else {
		pin = os.Getenv("PKCS11_PIN")
		label = os.Getenv("PKCS11_LABEL")
	}
	return lib, pin, label
}

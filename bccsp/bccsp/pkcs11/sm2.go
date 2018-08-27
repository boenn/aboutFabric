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
	"crypto/sm2"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"

	"github.com/hyperledger/fabric/bccsp"
)

type sm2Signature struct {
	R, S *big.Int
}

var (
	// curveHalfOrders contains the precomputed curve group orders halved.
	// It is used to ensure that signature' S value is lower or equal to the
	// curve group order halved. We accept only low-S signatures.
	// They are precomputed for efficiency reasons.
	curveHalfOrders map[elliptic.Curve]*big.Int = map[elliptic.Curve]*big.Int{
		sm2.P256_sm2(): new(big.Int).Rsh(sm2.P256_sm2().Params().N, 1),
	}
)

func marshalSM2Signature(r, s *big.Int) ([]byte, error) {
	return asn1.Marshal(sm2Signature{r, s})
}

func unmarshalSM2Signature(raw []byte) (*big.Int, *big.Int, error) {
	// Unmarshal
	sig := new(sm2Signature)
	_, err := asn1.Unmarshal(raw, sig)
	if err != nil {
		return nil, nil, fmt.Errorf("Failed unmashalling signature [%s]", err)
	}

	// Validate sig
	if sig.R == nil {
		return nil, nil, errors.New("Invalid signature. R must be different from nil.")
	}
	if sig.S == nil {
		return nil, nil, errors.New("Invalid signature. S must be different from nil.")
	}

	if sig.R.Sign() != 1 {
		return nil, nil, errors.New("Invalid signature. R must be larger than zero")
	}
	if sig.S.Sign() != 1 {
		return nil, nil, errors.New("Invalid signature. S must be larger than zero")
	}

	return sig.R, sig.S, nil
}

func (csp *impl) signSM2(k sm2PrivateKey, digest []byte, opts bccsp.SignerOpts) (signature []byte, err error) {
	r, s, err := csp.signP11SM2(k.ski, digest)
	if err != nil {
		return nil, err
	}

	// check for low-S
	halfOrder, ok := curveHalfOrders[k.pub.pub.Curve]
	if !ok {
		return nil, fmt.Errorf("Curve not recognized [%s]", k.pub.pub.Curve)
	}

	// is s > halfOrder Then
	if s.Cmp(halfOrder) == 1 {
		// Set s to N - s that will be then in the lower part of signature space
		// less or equal to half order
		s.Sub(k.pub.pub.Params().N, s)
	}

	return marshalSM2Signature(r, s)
}

func (csp *impl) verifySM2(k sm2PublicKey, signature, digest []byte, opts bccsp.SignerOpts) (valid bool, err error) {
	r, s, err := unmarshalSM2Signature(signature)
	if err != nil {
		return false, fmt.Errorf("Failed unmashalling signature [%s]", err)
	}

	// check for low-S
	halfOrder, ok := curveHalfOrders[k.pub.Curve]
	if !ok {
		return false, fmt.Errorf("Curve not recognized [%s]", k.pub.Curve)
	}

	// If s > halfOrder Then
	if s.Cmp(halfOrder) == 1 {
		return false, fmt.Errorf("Invalid S. Must be smaller than half the order [%s][%s].", s, halfOrder)
	}

	if csp.softVerify {
		return sm2.Verify(k.pub, digest, r, s), nil
	} else {
		return csp.verifyP11SM2(k.ski, digest, r, s, k.pub.Curve.Params().BitSize/8)
	}
}

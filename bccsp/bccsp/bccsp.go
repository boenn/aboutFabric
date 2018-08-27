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

package bccsp

import (
	"crypto"
	"hash"
)

// Key表示用于加密的密钥
type Key interface {
	// 如果允许此操作，则将此密钥转换为其字节表示形式。
	Bytes() ([]byte, error)
	// SKI返回此密钥的主体密钥标识符。
	SKI() []byte
	// 如果此密钥是对称密钥，则对称返回true，此密钥不对称则为false
	Symmetric() bool
	// 如果此密钥是私钥，Private返回true，否则返回false。
	Private() bool
	// PublicKey在非对称公钥/私钥对中返回的相应公钥部分。
	// 在对称密钥方案中返回错误。
	PublicKey() (Key, error)
}
// KeyGenOpts包含使用CSP进行密钥生成的选项。
type KeyGenOpts interface {
	// 算法返回将被使用的密钥生成算法标识符。
	Algorithm() string
	// 如果要生成的密钥必须是暂时的，则短暂返回true，否则返回false。
	Ephemeral() bool
}
// KeyDerivOpts包含用CSP进行密钥派生的选项。
type KeyDerivOpts interface {
	// 算法返回将被使用的密钥导出算法标识符。
	Algorithm() string
	// 如果派生的密钥必须是暂时的，则Ephemeral返回true，否则返回false。
	Ephemeral() bool
}
// KeyImportOpts contains options for importing the raw material of a key with a CSP.
// KeyImportOpts包含用CSP导入密钥的选项。
type KeyImportOpts interface {
	// 算法返回将被使用的密钥输入算法标识符。
	Algorithm() string
	// 如果导入的密钥必须是暂时的，则Ephemeral返回true，否则返回false。
	Ephemeral() bool
}
// HashOpts contains options for hashing with a CSP.
// HashOpts包含使用进行Hash操作的算法选项opts。
type HashOpts interface {

	// Algorithm returns the hash algorithm identifier (to be used).
	Algorithm() string
}

// SignerOpts contains options for signing with a CSP.
type SignerOpts interface {
	crypto.SignerOpts
}

// EncrypterOpts contains options for encrypting with a CSP.
type EncrypterOpts interface{}

// DecrypterOpts contains options for decrypting with a CSP.
type DecrypterOpts interface{}


type BCCSP interface {
	// KeyGen使用选项opts生成密钥。
	KeyGen(opts KeyGenOpts) (k Key, err error)

	// KeyDeriv使用选项opts从密钥中派生一个密钥。
	KeyDeriv(k Key, opts KeyDerivOpts) (dk Key, err error)

	// KeyImport使用选项opts从其原始表示中导入密钥。
	KeyImport(raw interface{}, opts KeyImportOpts) (k Key, err error)

	// GetKey返回密钥，这个密钥是与加密服务提供程序 (CSP)相关的
	// ski表示Subject Key Identifier(主体密钥标识符)
	GetKey(ski []byte) (k Key, err error)

	// Hash使用选项opts。如果opts为nil，则将使用默认的散列函数。
	Hash(msg []byte, opts HashOpts) (hash []byte, err error)

	// GetHash使用选项opts返回hash.Hash的实例。如果opts为nil，则将返回默认的散列函数。
	GetHash(opts HashOpts) (h hash.Hash, err error)

	// Sign使用密钥进行签名。选项opts参数应选择合适的算法。
	Sign(k Key, digest []byte, opts SignerOpts) (signature []byte, err error)

	// Verify根据密钥k和摘要验证签名。选项opts参数应选择合适的算法。
	Verify(k Key, signature, digest []byte, opts SignerOpts) (valid bool, err error)

	// Encrypt使用密钥k加密明文。选项opts参数应选择合适的算法。
	Encrypt(k Key, plaintext []byte, opts EncrypterOpts) (ciphertext []byte, err error)

	// Decrypt使用密钥k解密明文。选项opts参数应选择合适的算法。
	Decrypt(k Key, ciphertext []byte, opts DecrypterOpts) (plaintext []byte, err error)
}

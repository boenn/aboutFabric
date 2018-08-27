package bccsp

// ECDSAP256KeyGenOpts contains options for ECDSA key generation with curve P-256.
type SM2P256_sm2KeyGenOpts struct {
	Temporary bool
}

// Algorithm returns the key generation algorithm identifier (to be used).
func (opts *SM2P256_sm2KeyGenOpts) Algorithm() string {
	return SM2P256_sm2
}

// Ephemeral returns true if the key to generate has to be ephemeral,
// false otherwise.
func (opts *SM2P256_sm2KeyGenOpts) Ephemeral() bool {
	return opts.Temporary
}

// ECDSAP384KeyGenOpts contains options for ECDSA key generation with curve P-384.

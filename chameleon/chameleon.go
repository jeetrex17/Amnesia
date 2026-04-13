package chameleon

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"
)

var (
	one            = big.NewInt(1)
	modulusP       = mustBigIntFromHex("FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF")
	subgroupOrderQ = new(big.Int).Rsh(new(big.Int).Sub(new(big.Int).Set(modulusP), one), 1)
	generatorG     = big.NewInt(4)
	hashByteLen    = (modulusP.BitLen() + 7) / 8
	scalarByteLen  = (subgroupOrderQ.BitLen() + 7) / 8
)

type Store struct {
	PublicKey string `json:"public_key"`
	Trapdoor  string `json:"trapdoor"`
}

type PublicKey struct {
	value *big.Int
}

func Generate() (*Store, error) {
	trapdoor, err := randomNonZeroScalar()
	if err != nil {
		return nil, fmt.Errorf("generate chameleon trapdoor: %w", err)
	}

	publicValue := new(big.Int).Exp(generatorG, trapdoor, modulusP)
	return &Store{
		PublicKey: encodeHashElement(publicValue),
		Trapdoor:  encodeScalar(trapdoor),
	}, nil
}

func (s *Store) Validate() error {
	if s == nil {
		return fmt.Errorf("chameleon store is nil")
	}

	publicKey, err := s.Public()
	if err != nil {
		return err
	}
	trapdoor, err := s.trapdoorScalar()
	if err != nil {
		return err
	}

	derivedPublic := new(big.Int).Exp(generatorG, trapdoor, modulusP)
	if derivedPublic.Cmp(publicKey.value) != 0 {
		return fmt.Errorf("chameleon public key and trapdoor do not match")
	}

	return nil
}

func (s *Store) Public() (*PublicKey, error) {
	value, err := decodeHashElement(s.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("decode chameleon public key: %w", err)
	}
	if value.Sign() <= 0 || value.Cmp(modulusP) >= 0 {
		return nil, fmt.Errorf("chameleon public key out of range")
	}

	return &PublicKey{value: value}, nil
}

func GenerateRandomness() (string, error) {
	randomness, err := randomScalar()
	if err != nil {
		return "", fmt.Errorf("generate chameleon randomness: %w", err)
	}

	return encodeScalar(randomness), nil
}

func (p *PublicKey) Hash(message []byte, randomness string) (string, error) {
	if p == nil {
		return "", fmt.Errorf("chameleon public key is nil")
	}

	randomScalar, err := decodeScalar(randomness)
	if err != nil {
		return "", fmt.Errorf("decode chameleon randomness: %w", err)
	}

	messageScalar := messageDigestScalar(message)
	left := new(big.Int).Exp(generatorG, messageScalar, modulusP)
	right := new(big.Int).Exp(p.value, randomScalar, modulusP)
	hashValue := new(big.Int).Mod(new(big.Int).Mul(left, right), modulusP)

	return encodeHashElement(hashValue), nil
}

func (p *PublicKey) Verify(message []byte, randomness, expectedHash string) error {
	actualHash, err := p.Hash(message, randomness)
	if err != nil {
		return err
	}
	if !equalHexStrings(actualHash, expectedHash) {
		return fmt.Errorf("chameleon hash mismatch")
	}

	return nil
}

func (s *Store) ForgeCollision(oldMessage []byte, oldRandomness string, newMessage []byte) (string, error) {
	if err := s.Validate(); err != nil {
		return "", err
	}

	oldRandomScalar, err := decodeScalar(oldRandomness)
	if err != nil {
		return "", fmt.Errorf("decode previous chameleon randomness: %w", err)
	}
	trapdoor, err := s.trapdoorScalar()
	if err != nil {
		return "", err
	}

	inverseTrapdoor := new(big.Int).ModInverse(trapdoor, subgroupOrderQ)
	if inverseTrapdoor == nil {
		return "", fmt.Errorf("trapdoor is not invertible")
	}

	oldDigest := messageDigestScalar(oldMessage)
	newDigest := messageDigestScalar(newMessage)

	delta := new(big.Int).Sub(oldDigest, newDigest)
	delta.Mod(delta, subgroupOrderQ)

	adjustment := new(big.Int).Mul(delta, inverseTrapdoor)
	adjustment.Mod(adjustment, subgroupOrderQ)

	newRandomness := new(big.Int).Add(oldRandomScalar, adjustment)
	newRandomness.Mod(newRandomness, subgroupOrderQ)

	return encodeScalar(newRandomness), nil
}

func (s *Store) trapdoorScalar() (*big.Int, error) {
	trapdoor, err := decodeScalar(s.Trapdoor)
	if err != nil {
		return nil, fmt.Errorf("decode chameleon trapdoor: %w", err)
	}
	if trapdoor.Sign() == 0 {
		return nil, fmt.Errorf("chameleon trapdoor must be non-zero")
	}

	return trapdoor, nil
}

func randomNonZeroScalar() (*big.Int, error) {
	for {
		scalar, err := randomScalar()
		if err != nil {
			return nil, err
		}
		if scalar.Sign() != 0 {
			return scalar, nil
		}
	}
}

func randomScalar() (*big.Int, error) {
	return rand.Int(rand.Reader, subgroupOrderQ)
}

func messageDigestScalar(message []byte) *big.Int {
	sum := sha256.Sum256(message)
	digest := new(big.Int).SetBytes(sum[:])
	digest.Mod(digest, subgroupOrderQ)
	return digest
}

func encodeScalar(value *big.Int) string {
	return encodeBigInt(value, scalarByteLen)
}

func encodeHashElement(value *big.Int) string {
	return encodeBigInt(value, hashByteLen)
}

func encodeBigInt(value *big.Int, width int) string {
	return fmt.Sprintf("%0*x", width*2, value)
}

func decodeScalar(encoded string) (*big.Int, error) {
	return decodeBigInt(encoded, scalarByteLen, subgroupOrderQ)
}

func decodeHashElement(encoded string) (*big.Int, error) {
	return decodeBigInt(encoded, hashByteLen, modulusP)
}

func decodeBigInt(encoded string, width int, modulus *big.Int) (*big.Int, error) {
	cleaned := strings.TrimSpace(encoded)
	if cleaned == "" {
		return nil, fmt.Errorf("missing hex value")
	}
	raw, err := hex.DecodeString(cleaned)
	if err != nil {
		return nil, fmt.Errorf("decode hex: %w", err)
	}
	if len(raw) > width {
		return nil, fmt.Errorf("unexpected encoded length: %d", len(raw))
	}

	value := new(big.Int).SetBytes(raw)
	if value.Sign() < 0 || value.Cmp(modulus) >= 0 {
		return nil, fmt.Errorf("value out of range")
	}

	return value, nil
}

func equalHexStrings(left, right string) bool {
	return strings.EqualFold(strings.TrimSpace(left), strings.TrimSpace(right))
}

func mustBigIntFromHex(value string) *big.Int {
	n, ok := new(big.Int).SetString(value, 16)
	if !ok {
		panic(fmt.Sprintf("invalid hexadecimal constant: %s", value))
	}

	return n
}

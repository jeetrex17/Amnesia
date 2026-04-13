package chameleon

import "testing"

func TestForgeCollisionPreservesHash(t *testing.T) {
	store, err := Generate()
	if err != nil {
		t.Fatalf("generate store failed: %v", err)
	}
	publicKey, err := store.Public()
	if err != nil {
		t.Fatalf("load public key failed: %v", err)
	}

	oldMessage := []byte("original block link payload")
	newMessage := []byte("redacted block link payload")

	oldRandomness, err := GenerateRandomness()
	if err != nil {
		t.Fatalf("generate randomness failed: %v", err)
	}
	oldHash, err := publicKey.Hash(oldMessage, oldRandomness)
	if err != nil {
		t.Fatalf("hash original message failed: %v", err)
	}

	newRandomness, err := store.ForgeCollision(oldMessage, oldRandomness, newMessage)
	if err != nil {
		t.Fatalf("forge collision failed: %v", err)
	}

	if err := publicKey.Verify(newMessage, newRandomness, oldHash); err != nil {
		t.Fatalf("expected forged collision to preserve hash: %v", err)
	}
}

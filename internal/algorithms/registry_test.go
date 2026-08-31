package algorithms

import "testing"

func TestDefaultRegistryResolveAlias(t *testing.T) {
	registry := DefaultRegistry()

	entry, ok := registry.Resolve("Kyber768")
	if !ok {
		t.Fatal("expected alias to resolve")
	}
	if entry.CanonicalName != "ML-KEM-768" {
		t.Fatalf("expected canonical ML-KEM-768, got %s", entry.CanonicalName)
	}
}

func TestDefaultRegistryPreservesRuntimeBoundary(t *testing.T) {
	registry := DefaultRegistry()

	x25519mlkem, err := registry.MustResolve("X25519MLKEM768")
	if err != nil {
		t.Fatalf("resolve X25519MLKEM768: %v", err)
	}
	if !x25519mlkem.RuntimeSupported {
		t.Fatal("expected X25519MLKEM768 to be runtime-supported")
	}

	kem1024, err := registry.MustResolve("ML-KEM-1024")
	if err != nil {
		t.Fatalf("resolve ML-KEM-1024: %v", err)
	}
	if kem1024.RuntimeSupported {
		t.Fatal("expected ML-KEM-1024 to remain metadata-only")
	}
}

func TestDefaultRegistryRejectsUnknown(t *testing.T) {
	registry := DefaultRegistry()
	if _, ok := registry.Resolve("imaginary-pq"); ok {
		t.Fatal("expected unknown algorithm to be rejected")
	}
}

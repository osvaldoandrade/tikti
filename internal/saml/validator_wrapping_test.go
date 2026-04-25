package saml

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/beevik/etree"
)

// loadFixture reads a test XML fixture from testdata/.
func loadFixture(t *testing.T, name string) *etree.Document {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("failed to read fixture %s: %v", name, err)
	}
	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(data); err != nil {
		t.Fatalf("failed to parse fixture %s: %v", name, err)
	}
	return doc
}

// firstAssertion returns the first Assertion element in the document.
func firstAssertion(t *testing.T, doc *etree.Document) *etree.Element {
	t.Helper()
	el := doc.FindElement("//Assertion[@ID]")
	if el == nil {
		t.Fatal("no Assertion element found in fixture")
	}
	return el
}

// TestWrap_ExtendedWrap verifies detection of CVE-2012-5211 pattern:
// attacker wraps a malicious assertion outside the signed scope.
func TestWrap_ExtendedWrap(t *testing.T) {
	doc := loadFixture(t, "attack_wrap_extended.xml")
	signedRoot := firstAssertion(t, doc)
	refs := []string{"#_a1"}

	err := CheckSignedScope(doc, signedRoot, refs)
	if err != ErrSignatureWrapping {
		t.Errorf("expected ErrSignatureWrapping, got %v", err)
	}
}

// TestWrap_SiblingUnsigned verifies detection of an unsigned sibling assertion.
func TestWrap_SiblingUnsigned(t *testing.T) {
	doc := loadFixture(t, "attack_wrap_sibling.xml")
	signedRoot := firstAssertion(t, doc)
	refs := []string{"#_a1"}

	err := CheckSignedScope(doc, signedRoot, refs)
	if err != ErrSignatureWrapping {
		t.Errorf("expected ErrSignatureWrapping, got %v", err)
	}
}

// TestWrap_DuplicateID verifies detection of 2 elements sharing the same ID.
func TestWrap_DuplicateID(t *testing.T) {
	doc := loadFixture(t, "attack_wrap_duplicate_id.xml")
	signedRoot := firstAssertion(t, doc)
	refs := []string{"#_dup"}

	err := CheckSignedScope(doc, signedRoot, refs)
	if err != ErrSignatureWrapping {
		t.Errorf("expected ErrSignatureWrapping, got %v", err)
	}
}

// TestWrap_OutOfScopeReference verifies that a Reference URI pointing to an
// element outside signedRoot is rejected.
func TestWrap_OutOfScopeReference(t *testing.T) {
	doc := loadFixture(t, "attack_wrap_out_of_scope.xml")
	signedRoot := firstAssertion(t, doc)
	// Reference points to #_outside which is in <Extensions>, not inside the Assertion
	refs := []string{"#_outside"}

	err := CheckSignedScope(doc, signedRoot, refs)
	if err != ErrSignatureWrapping {
		t.Errorf("expected ErrSignatureWrapping, got %v", err)
	}
}

// TestWrap_AncestorMove verifies detection of the ancestor-move attack pattern
// where the signed assertion is moved into a wrapper and a malicious assertion
// is injected at the top level.
func TestWrap_AncestorMove(t *testing.T) {
	doc := loadFixture(t, "attack_wrap_ancestor_move.xml")
	// The signed assertion (_a1) was moved inside a <Wrapper>. The signature
	// scope (signedRoot) is the _a1 Assertion element itself. The malicious
	// assertion (_evil) sits outside the signed scope at the Response level.
	signedRoot := firstAssertion(t, doc)
	refs := []string{"#_a1"}

	err := CheckSignedScope(doc, signedRoot, refs)
	// _evil is NOT a descendant of signedRoot (_a1), so step 4 catches it.
	if err != ErrSignatureWrapping {
		t.Errorf("expected ErrSignatureWrapping, got %v", err)
	}
}

// TestWrap_ValidAssertion_Accept ensures 0 false positives for a legitimate
// single-assertion response.
func TestWrap_ValidAssertion_Accept(t *testing.T) {
	doc := loadFixture(t, "valid_assertion.xml")
	signedRoot := firstAssertion(t, doc)
	refs := []string{"#_a1"}

	err := CheckSignedScope(doc, signedRoot, refs)
	if err != nil {
		t.Errorf("expected nil error for valid assertion, got %v", err)
	}
}

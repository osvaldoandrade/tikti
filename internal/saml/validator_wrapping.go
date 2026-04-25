package saml

import (
	"strings"

	"github.com/beevik/etree"
)

// CheckSignedScope verifies that every reference URI resolves to an element
// that is a descendant of signedRoot, and that no ID collisions exist.
// This is the ancestor-walk defence against XML Signature Wrapping attacks
// per HLD §20, App. A.5.
func CheckSignedScope(doc *etree.Document, signedRoot *etree.Element,
	refs []string) error {

	// 1. build ID -> []element index across the whole document
	index := map[string][]*etree.Element{}
	for _, el := range doc.FindElements("//*[@ID]") {
		id := el.SelectAttrValue("ID", "")
		index[id] = append(index[id], el)
	}
	// 2. each reference must resolve to exactly 1 element
	for _, ref := range refs {
		id := strings.TrimPrefix(ref, "#")
		hits, ok := index[id]
		if !ok || len(hits) != 1 {
			return ErrSignatureWrapping
		}
		// 3. that element must be signedRoot or a descendant
		if !isDescendantOrSelf(signedRoot, hits[0]) {
			return ErrSignatureWrapping
		}
	}
	// 4. no sibling unsigned Assertion allowed
	for _, sib := range doc.FindElements("//Assertion[@ID]") {
		if !isDescendantOrSelf(signedRoot, sib) {
			return ErrSignatureWrapping
		}
	}
	return nil
}

// isDescendantOrSelf returns true if target is root itself or a descendant of root.
func isDescendantOrSelf(root, target *etree.Element) bool {
	for cur := target; cur != nil; cur = parentElement(cur) {
		if cur == root {
			return true
		}
	}
	return false
}

// parentElement returns the parent *etree.Element of el, or nil if the parent
// is the Document root.
func parentElement(el *etree.Element) *etree.Element {
	return el.Parent()
}

// Package tenantname defines the canonical display-name boundary shared by
// tenant writes and persisted inventory reads.
package tenantname

import (
	"strings"
	"unicode"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"
)

const protectedMasterSkeleton = "codefoundry"

// Normalize applies compatibility normalization before a name is persisted.
func Normalize(value string) string {
	return strings.TrimSpace(norm.NFKC.String(value))
}

// Valid rejects invisible, directional and control characters that can make a
// tenant label render differently from the value an administrator reviewed.
func Valid(value string) bool {
	value = Normalize(value)
	length := utf8.RuneCountInString(value)
	if length < 1 || length > 128 || !utf8.ValidString(value) {
		return false
	}
	for _, character := range value {
		if unicode.IsControl(character) || unicode.In(character, unicode.Cf, unicode.Zl, unicode.Zp) || !unicode.IsPrint(character) {
			return false
		}
	}
	return true
}

// ReservedMaster reports display names that collapse to the protected Code
// Foundry identity. Compatibility normalization, combining-mark removal and a
// confusable map cover punctuation, width, diacritic and cross-script
// impersonation variants. A bounded edit-distance check also closes deletion
// tricks where a currency/math symbol disappears from the alphanumeric
// skeleton while the remaining label still closely impersonates MASTER.
func ReservedMaster(value string) bool {
	return protectedShape(skeleton(value))
}

func protectedShape(candidate string) bool {
	// The product renders the authoritative tenant type next to the display
	// name. Reserve the protected brand even when an attacker appends or
	// prepends text such as "MASTER" to impersonate that composite label.
	if strings.Contains(candidate, protectedMasterSkeleton) {
		return true
	}
	characters := []rune(candidate)
	protected := []rune(protectedMasterSkeleton)
	const maximumDistance = 3
	if len(characters)-len(protected) > maximumDistance || len(protected)-len(characters) > maximumDistance {
		return false
	}
	previous := make([]int, len(protected)+1)
	for index := range previous {
		previous[index] = index
	}
	for leftIndex, left := range characters {
		current := make([]int, len(protected)+1)
		current[0] = leftIndex + 1
		for rightIndex, right := range protected {
			substitution := previous[rightIndex]
			if left != right {
				substitution++
			}
			current[rightIndex+1] = min(
				previous[rightIndex+1]+1,
				current[rightIndex]+1,
				substitution,
			)
		}
		previous = current
	}
	return previous[len(protected)] <= maximumDistance
}

func skeleton(value string) string {
	var result strings.Builder
	for _, character := range norm.NFKD.String(Normalize(value)) {
		if unicode.Is(unicode.Mn, character) || unicode.Is(unicode.Me, character) {
			continue
		}
		character = unicode.ToLower(character)
		if mapped, ok := protectedConfusable(character); ok {
			character = mapped
		}
		if unicode.IsLetter(character) || unicode.IsDigit(character) {
			result.WriteRune(character)
		}
	}
	return result.String()
}

func protectedConfusable(character rune) (rune, bool) {
	switch character {
	case '0':
		return 'o', true
	case '3':
		return 'e', true
	case 'с', 'ϲ', 'ꓚ', 'ᴄ':
		return 'c', true
	case 'о', 'ο', 'օ', 'ꓳ', 'ᴏ':
		return 'o', true
	case 'ԁ', 'ⅾ', 'ꓓ', 'ᴅ':
		return 'd', true
	case 'е', 'ε', 'ꓰ', 'ᴇ':
		return 'e', true
	case 'ғ', 'ϝ', 'ꓝ', 'ꜰ':
		return 'f', true
	case 'υ', 'ս', 'ꓴ', 'ᴜ':
		return 'u', true
	case 'ո', 'п', 'ꓠ', 'ɴ':
		return 'n', true
	case 'г', 'ρ', 'ꓣ', 'ʀ':
		return 'r', true
	case 'у', 'ү', 'ꓬ', 'ʏ':
		return 'y', true
	default:
		return 0, false
	}
}

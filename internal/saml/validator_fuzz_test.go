package saml

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// FuzzParseResponse exercises the centralized XML parser (parseXML) with
// arbitrary byte inputs. The seed corpus is drawn from the conformance
// suite fixtures in testdata/.
//
// The fuzz target must never panic or trigger a data race; returning an
// error from parseXML is perfectly acceptable for malformed input.
func FuzzParseResponse(f *testing.F) {
	// Seed corpus: every XML file in testdata/.
	entries, err := os.ReadDir("testdata")
	if err != nil {
		f.Fatalf("read testdata: %v", err)
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".xml") {
			continue
		}
		data, err := os.ReadFile(filepath.Join("testdata", e.Name()))
		if err != nil {
			f.Fatalf("read %s: %v", e.Name(), err)
		}
		f.Add(data)
	}

	// Additional hand-crafted seeds for XXE and edge cases.
	f.Add([]byte(`<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<foo>&xxe;</foo>`))

	f.Add([]byte(`<?xml version="1.0"?>
<!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
]>
<lolz>&lol2;</lolz>`))

	f.Add([]byte(`<Response/>`))
	f.Add([]byte(`not xml at all`))
	f.Add([]byte(``))

	f.Fuzz(func(t *testing.T, data []byte) {
		// parseXML must never panic regardless of input.
		// Errors are expected for malformed/malicious input.
		_, _ = parseXML(data)
	})
}

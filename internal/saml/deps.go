// Package saml provides SAML 2.0 single sign-on support.
//
// This file anchors the SAML module dependencies in go.mod so that
// go mod tidy does not remove them before the first feature PR lands.
package saml

import (
	_ "github.com/beevik/etree"
	_ "github.com/crewjam/saml"
	_ "github.com/fsnotify/fsnotify"
	_ "github.com/mattermost/xml-roundtrip-validator"
	_ "github.com/russellhaering/goxmldsig"
	_ "github.com/vmihailenco/msgpack/v5"
)

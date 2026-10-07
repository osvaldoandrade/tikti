package codeqbinding

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const testAssertion = "header.payload.signature"

func validTestRequest() AuthorityRequest {
	return AuthorityRequest{
		SchemaVersion: SchemaVersion, RequestID: "3f2b8c1e-7d4a-4e5f-9a0b-1c2d3e4f5a6b", TenantID: "conveste",
		ClusterRef: "conveste-hostgator", Namespace: "workload-conveste", ServiceAccountName: "cflow-codeq-worker-cf",
		ServiceAccountUID: "6b0f8a52-4c55-4f3c-9d1e-1a2b3c4d5e6f", PodUID: "0f9e8d7c-6b5a-4f3e-9d2c-1b0a9f8e7d6c",
	}
}

func resolvedBody(requestID string) string {
	return `{"schemaVersion":"codeq-binding-authority/v1","requestId":"` + requestID + `","allowed":true,"reason":"Resolved",` +
		`"bindings":[{"bindingUid":"b-1","generation":3,"topicId":"conveste.cflow-executar","topicName":"cflow-executar","policy":"Subscribe"}],` +
		`"excluded":[{"bindingUid":"","reason":"BindingNotReady","topicId":"conveste.other","policy":"Publish"}]}`
}

func authorityServer(t *testing.T, handler http.HandlerFunc) (*Client, *httptest.Server) {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	client, err := NewClient(server.URL+AuthorityPath, server.Client(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	return client, server
}

func writeDecision(w http.ResponseWriter, body string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	_, _ = io.WriteString(w, body)
}

func TestClientSendsExactRequestAndDecodesDecision(t *testing.T) {
	request := validTestRequest()
	client, _ := authorityServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != AuthorityPath || r.Header.Get("Authorization") != "Bearer "+testAssertion ||
			r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("unexpected request %s %s %v", r.Method, r.URL.Path, r.Header)
		}
		raw, _ := io.ReadAll(r.Body)
		var fields map[string]any
		if err := json.Unmarshal(raw, &fields); err != nil || len(fields) != 8 {
			t.Errorf("request body = %s", raw)
		}
		for _, key := range []string{"schemaVersion", "requestId", "tenantId", "clusterRef", "namespace", "serviceAccountName", "serviceAccountUid", "podUid"} {
			if _, ok := fields[key]; !ok {
				t.Errorf("request body missing %s", key)
			}
		}
		writeDecision(w, resolvedBody(request.RequestID))
	})
	decision, err := client.Authorize(context.Background(), request, testAssertion)
	if err != nil || !decision.IsAllowed() || len(decision.Bindings) != 1 || decision.Bindings[0].Generation != 3 || len(decision.Excluded) != 1 {
		t.Fatalf("Authorize() = %#v, %v", decision, err)
	}
}

func TestClientAcceptsAllowedWithoutBindingsAndDenials(t *testing.T) {
	request := validTestRequest()
	for name, body := range map[string]string{
		"allowed empty":     `{"schemaVersion":"codeq-binding-authority/v1","requestId":"` + request.RequestID + `","allowed":true,"reason":"Resolved","bindings":[],"excluded":[]}`,
		"allowed omitted":   `{"schemaVersion":"codeq-binding-authority/v1","requestId":"` + request.RequestID + `","allowed":true,"reason":"Resolved"}`,
		"denied with lists": `{"schemaVersion":"codeq-binding-authority/v1","requestId":"` + request.RequestID + `","allowed":false,"reason":"PlacementMismatch","bindings":[],"excluded":[]}`,
	} {
		client, _ := authorityServer(t, func(w http.ResponseWriter, _ *http.Request) { writeDecision(w, body) })
		if _, err := client.Authorize(context.Background(), request, testAssertion); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
	}
}

func TestClientFailsClosedOnInvalidResponses(t *testing.T) {
	request := validTestRequest()
	base := resolvedBody(request.RequestID)
	tests := map[string]struct {
		handler http.HandlerFunc
		want    error
	}{
		"500":              {func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(500) }, ErrAuthorityUnavailable},
		"429":              {func(w http.ResponseWriter, _ *http.Request) { w.Header().Set("Retry-After", "1"); w.WriteHeader(429) }, ErrAuthorityUnavailable},
		"404 public route": {func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(404) }, ErrAuthorityUnavailable},
		"redirect": {func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "https://attacker.example"+AuthorityPath, http.StatusTemporaryRedirect)
		}, ErrAuthorityUnavailable},
		"no-store missing": {func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Pragma", "no-cache")
			_, _ = io.WriteString(w, base)
		}, ErrAuthorityInvalidResponse},
		"pragma missing": {func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Cache-Control", "no-store")
			_, _ = io.WriteString(w, base)
		}, ErrAuthorityInvalidResponse},
		"content type": {func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "text/plain")
			w.Header().Set("Cache-Control", "no-store")
			w.Header().Set("Pragma", "no-cache")
			_, _ = io.WriteString(w, base)
		}, ErrAuthorityInvalidResponse},
		"unknown field": {func(w http.ResponseWriter, _ *http.Request) {
			writeDecision(w, strings.Replace(base, `"allowed"`, `"cached":true,"allowed"`, 1))
		}, ErrAuthorityInvalidResponse},
		"unknown binding field": {func(w http.ResponseWriter, _ *http.Request) {
			writeDecision(w, strings.Replace(base, `"policy":"Subscribe"`, `"policy":"Subscribe","token":"x"`, 1))
		}, ErrAuthorityInvalidResponse},
		"trailing data": {func(w http.ResponseWriter, _ *http.Request) { writeDecision(w, base+"{}") }, ErrAuthorityInvalidResponse},
		"empty body":    {func(w http.ResponseWriter, _ *http.Request) { writeDecision(w, "") }, ErrAuthorityInvalidResponse},
		"requestId echo": {func(w http.ResponseWriter, _ *http.Request) {
			writeDecision(w, resolvedBody("11111111-2222-4333-8444-555555555555"))
		}, ErrAuthorityInvalidResponse},
		"schema version": {func(w http.ResponseWriter, _ *http.Request) {
			writeDecision(w, strings.Replace(base, "authority/v1", "authority/v2", 1))
		}, ErrAuthorityInvalidResponse},
		"allowed missing": {func(w http.ResponseWriter, _ *http.Request) {
			writeDecision(w, strings.Replace(base, `"allowed":true,`, "", 1))
		}, ErrAuthorityInvalidResponse},
		"fractional gen": {func(w http.ResponseWriter, _ *http.Request) {
			writeDecision(w, strings.Replace(base, `"generation":3`, `"generation":3.5`, 1))
		}, ErrAuthorityInvalidResponse},
		"oversized": {func(w http.ResponseWriter, _ *http.Request) {
			writeDecision(w, base+strings.Repeat(" ", maxResponseBytes))
		}, ErrAuthorityInvalidResponse},
		"denied with lists": {func(w http.ResponseWriter, _ *http.Request) {
			writeDecision(w, strings.Replace(base, `"allowed":true,"reason":"Resolved"`, `"allowed":false,"reason":"ServiceNotFound"`, 1))
		}, ErrAuthorityInvalidResponse},
	}
	for name, test := range tests {
		client, _ := authorityServer(t, test.handler)
		decision, err := client.Authorize(context.Background(), request, testAssertion)
		if !errors.Is(err, test.want) || decision.Allowed != nil {
			t.Fatalf("%s: decision=%#v err=%v want %v", name, decision, err, test.want)
		}
	}
}

func TestClientTimeoutAndNoRetry(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		select {
		case <-r.Context().Done():
		case <-time.After(3 * time.Second):
		}
	}))
	t.Cleanup(server.Close)
	client, err := NewClient(server.URL+AuthorityPath, server.Client(), 100*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	if _, err := client.Authorize(context.Background(), validTestRequest(), testAssertion); !errors.Is(err, ErrAuthorityUnavailable) {
		t.Fatalf("timeout err = %v", err)
	}
	if elapsed := time.Since(started); elapsed > 2*time.Second {
		t.Fatalf("timeout not enforced: %v", elapsed)
	}
	if calls.Load() != 1 {
		t.Fatalf("authority called %d times; retries are forbidden", calls.Load())
	}
	// A cancelled caller context also fails closed.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := client.Authorize(ctx, validTestRequest(), testAssertion); !errors.Is(err, ErrAuthorityUnavailable) {
		t.Fatalf("cancelled err = %v", err)
	}
}

func TestClientRefusesInvalidInputsLocally(t *testing.T) {
	var calls atomic.Int32
	client, _ := authorityServer(t, func(w http.ResponseWriter, _ *http.Request) { calls.Add(1) })
	bad := validTestRequest()
	bad.PodUID = "not-a-uuid"
	for name, run := range map[string]func() error{
		"invalid request": func() error { _, err := client.Authorize(context.Background(), bad, testAssertion); return err },
		"empty assertion": func() error { _, err := client.Authorize(context.Background(), validTestRequest(), ""); return err },
		"huge assertion": func() error {
			_, err := client.Authorize(context.Background(), validTestRequest(), strings.Repeat("a", maxAssertion+1))
			return err
		},
	} {
		if err := run(); !errors.Is(err, ErrAuthorityUnavailable) {
			t.Fatalf("%s: %v", name, err)
		}
	}
	if calls.Load() != 0 {
		t.Fatal("invalid input reached the authority")
	}
	for _, endpoint := range []string{"", "https://api.example/other", "ftp://api.example" + AuthorityPath} {
		if _, err := NewClient(endpoint, http.DefaultClient, time.Second); err == nil {
			t.Fatalf("NewClient(%q) accepted", endpoint)
		}
	}
	if _, err := NewClient("https://api.example"+AuthorityPath, http.DefaultClient, 11*time.Second); err == nil {
		t.Fatal("timeout above 10 s accepted")
	}
}

func TestValidDecisionRules(t *testing.T) {
	request := validTestRequest()
	allowed := true
	binding := Binding{BindingUID: "b-1", Generation: 1, TopicID: "conveste.cflow-executar", TopicName: "cflow-executar", Policy: PolicyPublish}
	base := AuthorityDecision{SchemaVersion: SchemaVersion, RequestID: request.RequestID, Allowed: &allowed, Reason: ReasonResolved, Bindings: []Binding{binding}}
	if !ValidDecision(request, base) {
		t.Fatal("valid decision rejected")
	}
	tooMany := base
	tooMany.Bindings = nil
	for index := 0; index <= MaxBindings; index++ {
		b := binding
		b.BindingUID = "b-" + strings.Repeat("x", index+1)
		tooMany.Bindings = append(tooMany.Bindings, b)
	}
	denied := false
	cases := map[string]func(AuthorityDecision) AuthorityDecision{
		"allowed with other reason": func(d AuthorityDecision) AuthorityDecision { d.Reason = "PlacementMismatch"; return d },
		"denied unknown reason": func(d AuthorityDecision) AuthorityDecision {
			d.Allowed, d.Reason, d.Bindings = &denied, "Whatever", nil
			return d
		},
		"denied resolved": func(d AuthorityDecision) AuthorityDecision {
			d.Allowed, d.Reason, d.Bindings = &denied, ReasonResolved, nil
			return d
		},
		"denied with excluded": func(d AuthorityDecision) AuthorityDecision {
			d.Allowed, d.Reason, d.Bindings = &denied, "ServiceNotFound", nil
			d.Excluded = []Excluded{{Reason: "TopicNotReady", TopicID: "conveste.x"}}
			return d
		},
		"too many": func(AuthorityDecision) AuthorityDecision { return tooMany },
		"generation zero": func(d AuthorityDecision) AuthorityDecision {
			d.Bindings = []Binding{{BindingUID: "b", Generation: 0, TopicID: binding.TopicID, TopicName: binding.TopicName, Policy: PolicyPublish}}
			return d
		},
		"cross tenant topic": func(d AuthorityDecision) AuthorityDecision {
			d.Bindings = []Binding{{BindingUID: "b", Generation: 1, TopicID: "wecare.cflow-executar", TopicName: "cflow-executar", Policy: PolicyPublish}}
			return d
		},
		"topic id with tenant prefix in name": func(d AuthorityDecision) AuthorityDecision {
			d.Bindings = []Binding{{BindingUID: "b", Generation: 1, TopicID: "conveste.conveste.x", TopicName: "conveste.x", Policy: PolicyPublish}}
			return d
		},
		"invalid policy": func(d AuthorityDecision) AuthorityDecision {
			d.Bindings = []Binding{{BindingUID: "b", Generation: 1, TopicID: binding.TopicID, TopicName: binding.TopicName, Policy: "Admin"}}
			return d
		},
		"empty binding uid": func(d AuthorityDecision) AuthorityDecision {
			d.Bindings = []Binding{{Generation: 1, TopicID: binding.TopicID, TopicName: binding.TopicName, Policy: PolicyPublish}}
			return d
		},
		"duplicate uid": func(d AuthorityDecision) AuthorityDecision {
			d.Bindings = []Binding{binding, binding}
			return d
		},
		"excluded unknown reason": func(d AuthorityDecision) AuthorityDecision {
			d.Excluded = []Excluded{{Reason: "Other", TopicID: "conveste.x"}}
			return d
		},
		"excluded other tenant": func(d AuthorityDecision) AuthorityDecision {
			d.Excluded = []Excluded{{Reason: "TopicNotReady", TopicID: "wecare.x"}}
			return d
		},
		"excluded control char": func(d AuthorityDecision) AuthorityDecision {
			d.Excluded = []Excluded{{Reason: "PolicyInvalid", TopicID: "conveste.x", Policy: "a\nb"}}
			return d
		},
	}
	for name, mutate := range cases {
		if ValidDecision(request, mutate(base)) {
			t.Fatalf("%s accepted", name)
		}
	}
}

func TestValidRequestShapes(t *testing.T) {
	if !ValidRequest(validTestRequest()) {
		t.Fatal("valid request rejected")
	}
	for name, mutate := range map[string]func(*AuthorityRequest){
		"schema":    func(r *AuthorityRequest) { r.SchemaVersion = "v0" },
		"requestId": func(r *AuthorityRequest) { r.RequestID = "abc" },
		"tenant":    func(r *AuthorityRequest) { r.TenantID = "C" },
		"cluster":   func(r *AuthorityRequest) { r.ClusterRef = "Conveste" },
		"namespace": func(r *AuthorityRequest) { r.Namespace = "a_b" },
		"sa":        func(r *AuthorityRequest) { r.ServiceAccountName = strings.Repeat("a", 254) },
		"sa uid":    func(r *AuthorityRequest) { r.ServiceAccountUID = "" },
		"pod uid":   func(r *AuthorityRequest) { r.PodUID = strings.ToUpper(r.PodUID) },
	} {
		request := validTestRequest()
		mutate(&request)
		if ValidRequest(request) {
			t.Fatalf("%s accepted", name)
		}
	}
}

// apiConflictBody is shaped exactly like code-admin-api's
// CodeQBindingAuthorityDecisionV1 for one Service with two QueueTopic
// bindings: aa-first (sorts first, eligible) and zz-second (QueueBindingConflict).
func apiConflictBody(requestID string) string {
	return `{"schemaVersion":"codeq-binding-authority/v1","requestId":"` + requestID + `","allowed":true,"reason":"Resolved",` +
		`"bindings":[{"bindingUid":"8d0c2a3e-0b7e-4c1f-9f3a-aa0000000001","generation":2,"topicId":"conveste.cflow-executar","topicName":"cflow-executar","policy":"Subscribe"}],` +
		`"excluded":[{"bindingUid":"8d0c2a3e-0b7e-4c1f-9f3a-zz0000000002","reason":"QueueBindingConflict","topicId":"conveste.cflow-relatorios","policy":"Publish"},` +
		`{"bindingUid":"","reason":"PolicyInvalid","topicId":"conveste.cflow-legado","policy":""}]}`
}

func TestClientAcceptsAPIShapedQueueBindingConflictExclusion(t *testing.T) {
	request := validTestRequest()
	client, _ := authorityServer(t, func(w http.ResponseWriter, _ *http.Request) {
		writeDecision(w, apiConflictBody(request.RequestID))
	})
	decision, err := client.Authorize(context.Background(), request, testAssertion)
	if err != nil {
		t.Fatalf("API-shaped conflict response refused: %v", err)
	}
	if !decision.IsAllowed() || len(decision.Bindings) != 1 || decision.Bindings[0].TopicName != "cflow-executar" {
		t.Fatalf("primary binding lost: %#v", decision)
	}
	if len(decision.Excluded) != 2 || decision.Excluded[0].Reason != ExclusionQueueBindingConflict ||
		decision.Excluded[0].TopicID != "conveste.cflow-relatorios" {
		t.Fatalf("conflict exclusion not decoded: %#v", decision.Excluded)
	}
}

// The closed vocabularies must equal code-admin-api's
// CodeQBindingAuthorityDecisionReasons / CodeQBindingAuthorityExclusionReasons
// (internal/domain/codeq_binding_authority.go) and the OpenAPI enums. A reason
// the API can emit but Tikti does not know turns every decision into 503.
func TestReasonVocabulariesEqualTheAPI(t *testing.T) {
	apiDecision := []string{"Resolved", "NamespaceNotBound", "ServiceNotFound", "ServiceAmbiguous", "ServiceNotReady",
		"PlacementMismatch", "PlacementAmbiguous", "TooManyBindings"}
	apiExclusion := []string{"TargetKindUnsupported", "QueueBindingConflict", "PolicyInvalid", "OwnerMismatch", "BindingNotReady",
		"TopicNotFound", "TopicTenantMismatch", "TopicNotReady", "TopicIdentityMismatch"}
	for name, pair := range map[string][2][]string{
		"decision":  {DecisionReasons(), apiDecision},
		"exclusion": {ExclusionReasons(), apiExclusion},
	} {
		got, want := slices.Clone(pair[0]), slices.Clone(pair[1])
		slices.Sort(got)
		slices.Sort(want)
		if !slices.Equal(got, want) {
			t.Fatalf("%s vocabulary = %v, API = %v", name, got, want)
		}
	}
	request := validTestRequest()
	allowed, denied := true, false
	for _, reason := range apiExclusion {
		decision := AuthorityDecision{SchemaVersion: SchemaVersion, RequestID: request.RequestID, Allowed: &allowed, Reason: ReasonResolved,
			Excluded: []Excluded{{BindingUID: "b-1", Reason: reason, TopicID: "conveste.x", Policy: PolicyPublish}}}
		if !ValidDecision(request, decision) {
			t.Fatalf("exclusion reason %s refused", reason)
		}
	}
	for _, reason := range apiDecision[1:] {
		decision := AuthorityDecision{SchemaVersion: SchemaVersion, RequestID: request.RequestID, Allowed: &denied, Reason: reason}
		if !ValidDecision(request, decision) {
			t.Fatalf("decision reason %s refused", reason)
		}
	}
}

func TestClientClassifiesAuthorityFailures(t *testing.T) {
	const bodyMarker = "authority-error-body-marker"
	request := validTestRequest()
	for status, wantClass := range map[int]string{
		http.StatusTooManyRequests:     FailureThrottled,
		http.StatusServiceUnavailable:  FailureThrottled,
		http.StatusUnauthorized:        FailureRejected,
		http.StatusForbidden:           FailureRejected,
		http.StatusInternalServerError: FailureStatus,
		http.StatusNotFound:            FailureStatus,
		http.StatusBadRequest:          FailureStatus,
	} {
		client, _ := authorityServer(t, func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(status)
			_, _ = io.WriteString(w, `{"error":"`+bodyMarker+`"}`)
		})
		_, err := client.Authorize(context.Background(), request, testAssertion)
		class, gotStatus := ClassifyFailure(err)
		if !errors.Is(err, ErrAuthorityUnavailable) || class != wantClass || gotStatus != status {
			t.Fatalf("status %d: err=%v class=%s status=%d, want %s", status, err, class, gotStatus, wantClass)
		}
		if strings.Contains(err.Error(), bodyMarker) {
			t.Fatalf("status %d: error carries the response body: %v", status, err)
		}
	}

	client, _ := authorityServer(t, func(w http.ResponseWriter, _ *http.Request) { writeDecision(w, "{}") })
	_, err := client.Authorize(context.Background(), request, testAssertion)
	if class, status := ClassifyFailure(err); !errors.Is(err, ErrAuthorityInvalidResponse) || class != FailureInvalid || status != http.StatusOK {
		t.Fatalf("invalid 200: err=%v class=%s status=%d", err, class, status)
	}

	bad := validTestRequest()
	bad.PodUID = "not-a-uuid"
	_, err = client.Authorize(context.Background(), bad, testAssertion)
	if class, status := ClassifyFailure(err); class != FailureLocal || status != 0 {
		t.Fatalf("local: class=%s status=%d", class, status)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = client.Authorize(ctx, request, testAssertion)
	if class, status := ClassifyFailure(err); !errors.Is(err, ErrAuthorityUnavailable) || class != FailureTransport || status != 0 {
		t.Fatalf("transport: err=%v class=%s status=%d", err, class, status)
	}

	// Errors from other Authority implementations fold into closed classes.
	if class, _ := ClassifyFailure(context.DeadlineExceeded); class != FailureTransport {
		t.Fatalf("foreign error class = %s", class)
	}
	if class, _ := ClassifyFailure(ErrAuthorityInvalidResponse); class != FailureInvalid {
		t.Fatalf("bare invalid class = %s", class)
	}
}

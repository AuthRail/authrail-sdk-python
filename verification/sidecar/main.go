// An isolated real-handler check. It creates no tenant records or provider effects.
package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"time"

	"github.com/AuthRail/authrail-sidecar/sidecar"
)

func main() {
	const organisation = "00000000-0000-4000-8000-000000000001"
	const deployment = "00000000-0000-4000-8000-000000000002"
	const inventory = "00000000-0000-4000-8000-000000000003"
	const revision = "00000000-0000-4000-8000-000000000004"
	const bundle = "00000000-0000-4000-8000-000000000005"
	const operation = "00000000-0000-4000-8000-000000000008"
	private, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&private.PublicKey)
	if err != nil {
		panic(err)
	}
	digest := sha256.Sum256(der)
	pin := hex.EncodeToString(digest[:])
	rules := []map[string]any{}
	for _, phase := range []string{"tool_call", "tool_result"} {
		for _, comparison := range []string{"lte", "gt"} {
			outcome := "allow"
			if comparison == "gt" {
				outcome = "deny"
			}
			rules = append(rules, map[string]any{"id": phase + comparison, "phase": phase,
				"when": map[string]any{"kind": "compare", "left": map[string]any{
					"root": "arguments", "path": []string{"amount"}}, "comparison": comparison,
					"right": map[string]any{"kind": "literal", "value": 100}}, "outcome": outcome})
		}
	}
	now := time.Now().UTC()
	manifest := map[string]any{"formatVersion": 1, "bundleId": bundle,
		"organisationId": organisation, "deploymentId": deployment,
		"inventoryItemId": inventory, "inventoryRevisionId": revision, "sequence": 1,
		"mode": "observe", "issuedAt": now.Add(-time.Minute),
		"activeFrom": now.Add(-time.Minute), "expiresAt": now.Add(time.Hour),
		"rails": []any{map[string]any{"railId": inventory, "versionId": revision,
			"operationVersionId": operation, "kind": "policy", "operationContract": map[string]any{
				"requiredCoverage": []string{"tool_call", "tool_result"}},
			"content": map[string]any{"formatVersion": 2, "rules": rules}}}}
	payload, err := json.Marshal(manifest)
	if err != nil {
		panic(err)
	}
	hash := sha256.Sum256(payload)
	signature, err := ecdsa.SignASN1(rand.Reader, private, hash[:])
	if err != nil {
		panic(err)
	}
	configuration := map[string]any{
		"deployment": map[string]any{"organisationId": organisation, "deploymentId": deployment,
			"inventoryItemId": inventory, "inventoryRevisionId": revision, "mode": "observe",
			"sequence": 1, "activeBundleId": bundle},
		"bundle": map[string]any{"payload": base64.RawURLEncoding.EncodeToString(payload),
			"keyId": "verification", "algorithm": "ECDSA_SHA_256",
			"signature": base64.StdEncoding.EncodeToString(signature),
			"verificationKey": map[string]any{"format": "spki-der",
				"base64": base64.StdEncoding.EncodeToString(der), "sha256": pin}}}
	control := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/runtime/deployment/configuration" {
			// No central retention is simulated: the real sidecar must queue reports.
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		_ = json.NewEncoder(w).Encode(configuration)
	}))
	defer control.Close()
	public := ed25519.NewKeyFromSeed(make([]byte, 32)).Public().(ed25519.PublicKey)
	syncer, err := sidecar.NewSynchronizer(sidecar.Options{ControlPlaneURL: control.URL,
		Token: "verification-deployment-token", OrganisationID: organisation, DeploymentID: deployment,
		TrustedPins: map[string]struct{}{pin: {}}, ExecutorPublicKey: public,
		StateFile: filepath.Join(os.Args[1], "state.json")})
	if err != nil {
		panic(err)
	}
	if err := syncer.Sync(context.Background()); err != nil {
		panic(err)
	}
	server := httptest.NewServer(sidecar.EvaluationHandler(syncer,
		"cccccccccccccccccccccccccccccccc"))
	defer server.Close()
	fmt.Println(server.URL)
	// EOF lets the Python parent end this exact isolated process gracefully.
	_, _ = fmt.Scanln()
}

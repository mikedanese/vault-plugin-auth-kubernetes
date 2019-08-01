package kubeauth

import (
	"context"
	"crypto/rsa"
	"fmt"
	"testing"

	authv1 "k8s.io/api/authentication/v1"

	"github.com/hashicorp/errwrap"
	multierror "github.com/hashicorp/go-multierror"
	"github.com/hashicorp/vault/sdk/logical"
)

const (
	testNamespace = "default"
	testName      = "vault-auth"
	testUID       = "d77f89bc-9055-11e7-a068-0800276d99bf"
	invalidName   = "vault-invalid"
	invalidUID    = "044fd4f1-974d-11e7-9a15-0800276d99bf"

	testGlobbedNamespace = "def*"
	testGlobbedName      = "vault-*"
)

var (
	testDefaultPEMs = []string{testECCert, testRSACert}
)

// mock review is used while testing
type mockTokenReview struct {
	saName      string
	saNamespace string
	saUID       string
}

func (t mockTokenReview) Review(tr *authv1.TokenReview) (*authv1.TokenReview, error) {
	return &authv1.TokenReview{
		Spec: tr.Spec,
		Status: authv1.TokenReviewStatus{
			User: authv1.UserInfo{
				Username: fmt.Sprintf("system:serviceaccount:%s:%s", t.saNamespace, t.saName),
				UID:      t.saUID,
			},
		},
	}, nil
}

func setupBackend(t *testing.T, tr tokenReviewer, config, role map[string]interface{}) (logical.Backend, logical.Storage) {
	b, storage := getBackend(t)

	setConfigOrDie(t, b, storage, map[string]interface{}{
		"pem_keys":           testDefaultPEMs,
		"kubernetes_host":    "host",
		"kubernetes_ca_cert": testCACert,
	})
	if config != nil {
		setConfigOrDie(t, b, storage, config)
	}

	setRoleOrDie(t, b, storage, map[string]interface{}{
		"bound_service_account_names":      testName,
		"bound_service_account_namespaces": testNamespace,
		"policies":                         "test",
		"period":                           "3s",
		"ttl":                              "1s",
		"num_uses":                         12,
		"max_ttl":                          "5s",
	})
	if role != nil {
		setRoleOrDie(t, b, storage, role)
	}

	if tr == nil {
		tr = mockTokenReview{
			saName:      testName,
			saNamespace: testNamespace,
			saUID:       testUID,
		}
	}
	b.(*kubeAuthBackend).reviewFactory = func(*kubeConfig) tokenReviewer {
		return tr
	}
	return b, storage
}

func setConfigOrDie(t *testing.T, b logical.Backend, s logical.Storage, config map[string]interface{}) {
	t.Helper()
	reqOrDie(t, b, s, &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "config",
		Data:      config,
	})
}

func setRoleOrDie(t *testing.T, b logical.Backend, s logical.Storage, role map[string]interface{}) {
	t.Helper()
	reqOrDie(t, b, s, &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "role/plugin-test",
		Storage:   s,
		Data:      role,
	})
}

func reqOrDie(t *testing.T, b logical.Backend, s logical.Storage, req *logical.Request) *logical.Response {
	t.Helper()
	req.Storage = s
	resp, err := b.HandleRequest(context.Background(), req)
	if err != nil || resp.IsError() {
		t.Fatalf("unexpected error: %v resp: %#v\n", err, resp)
	}
	return resp
}

func TestLogin(t *testing.T) {
	tests := map[string]struct {
		data         map[string]interface{}
		config, role map[string]interface{}
		tokenReview  tokenReviewer

		expectErrStr string
	}{
		"no role in data": {
			data: map[string]interface{}{
				"jwt": jwtData,
			},

			expectErrStr: "missing role",
		},
		"no jwt in data": {
			data: map[string]interface{}{
				"role": "plugin-test",
			},

			expectErrStr: "missing jwt",
		},
		"bad role": {
			data: map[string]interface{}{
				"role": "plugin-test-bad",
				"jwt":  jwtData,
			},

			expectErrStr: `invalid role name "plugin-test-bad"`,
		},
		"bad jwt service account name": {
			data: map[string]interface{}{
				"role": "plugin-test",
				"jwt":  jwtBadServiceAccount,
			},

			expectErrStr: `JWT names did not match`,
		},
		"unauthorized jwt service account": {
			data: map[string]interface{}{
				"role": "plugin-test",
				"jwt":  jwtBadServiceAccount,
			},
			tokenReview: mockTokenReview{
				saName:      invalidName,
				saNamespace: testNamespace,
				saUID:       invalidUID,
			},

			expectErrStr: `service account name not authorized`,
		},
		"bad jwt signing key": {
			data: map[string]interface{}{
				"role": "plugin-test",
				"jwt":  jwtWithBadSigningKey,
			},

			expectErrStr: multierror.Append(nil,
				errwrap.Wrapf("failed to validate JWT: {{err}}", errMismatchedSigningMethod),
				errwrap.Wrapf("failed to validate JWT: {{err}}", rsa.ErrVerification),
			).Error(),
		},

		"successful": {
			data: map[string]interface{}{
				"role": "plugin-test",
				"jwt":  jwtData,
			},
		},
		"successful globbed name": {
			data: map[string]interface{}{
				"role": "plugin-test",
				"jwt":  jwtData,
			},
			role: map[string]interface{}{
				"bound_service_account_names":      testGlobbedName,
				"bound_service_account_namespaces": testNamespace,
			},
		},
		"successful globbed namespace": {
			data: map[string]interface{}{
				"role": "plugin-test",
				"jwt":  jwtData,
			},
			role: map[string]interface{}{
				"bound_service_account_names":      testName,
				"bound_service_account_namespaces": testGlobbedNamespace,
			},
		},
		"successful ecdsa": {
			data: map[string]interface{}{
				"role": "plugin-test",
				"jwt":  jwtECDSASigned,
			},
			config: map[string]interface{}{
				"pem_keys":           []string{ecdsaKey},
				"kubernetes_host":    "host",
				"kubernetes_ca_cert": testCACert,
			},
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			b, storage := setupBackend(t, test.tokenReview, test.config, test.role)
			req := &logical.Request{
				Operation: logical.UpdateOperation,
				Path:      "login",
				Storage:   storage,
				Data:      test.data,
			}
			resp, err := b.HandleRequest(context.Background(), req)
			if test.expectErrStr != "" {
				if !resp.IsError() && err == nil {
					t.Fatalf("expected error: err=%v resp=%#v", err, resp)
				}

				if resp.IsError() {
					err = resp.Error()
				}

				if want, got := test.expectErrStr, err.Error(); want != got {
					t.Fatalf("unexpected error: want=%q got=%q", want, got)
				}
				return
			}

			if resp.IsError() || err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestAliasLookAhead(t *testing.T) {
	b, storage := setupBackend(t, nil, nil, nil)

	data := map[string]interface{}{
		"jwt": jwtData,
	}

	resp := reqOrDie(t, b, storage, &logical.Request{
		Operation: logical.AliasLookaheadOperation,
		Path:      "login",
		Storage:   storage,
		Data:      data,
		Connection: &logical.Connection{
			RemoteAddr: "127.0.0.1",
		},
	})

	if resp.Auth.Alias.Name != testUID {
		t.Fatalf("Unexpected UID: %s", resp.Auth.Alias.Name)
	}
}

var jwtData = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJrdWJlcm5ldGVzL3NlcnZpY2VhY2NvdW50Iiwia3ViZXJuZXRlcy5pby9zZXJ2aWNlYWNjb3VudC9uYW1lc3BhY2UiOiJkZWZhdWx0Iiwia3ViZXJuZXRlcy5pby9zZXJ2aWNlYWNjb3VudC9zZWNyZXQubmFtZSI6InZhdWx0LWF1dGgtdG9rZW4tdDVwY24iLCJrdWJlcm5ldGVzLmlvL3NlcnZpY2VhY2NvdW50L3NlcnZpY2UtYWNjb3VudC5uYW1lIjoidmF1bHQtYXV0aCIsImt1YmVybmV0ZXMuaW8vc2VydmljZWFjY291bnQvc2VydmljZS1hY2NvdW50LnVpZCI6ImQ3N2Y4OWJjLTkwNTUtMTFlNy1hMDY4LTA4MDAyNzZkOTliZiIsInN1YiI6InN5c3RlbTpzZXJ2aWNlYWNjb3VudDpkZWZhdWx0OnZhdWx0LWF1dGgifQ.HKUcqgrvan5ZC_mnpaMEx4RW3KrhfyH_u8G_IA2vUfkLK8tH3T7fJuJaPr7W6K_BqCrbeM5y3owszOzb4NR0Lvw6GBt2cFcen2x1Ua4Wokr0bJjTT7xQOIOw7UvUDyVS17wAurlfUnmWMwMMMOebpqj5K1t6GnyqghH1wPdHYRGX-q5a6C323dBCgM5t6JY_zTTaBgM6EkFq0poBaifmSMiJRPrdUN_-IgyK8fgQRiFYYkgS6DMIU4k4nUOb_sUFf5xb8vMs3SMteKiuWFAIt4iszXTj5IyBUNqe0cXA3zSY3QiNCV6bJ2CWW0Qf9WDtniT79VAqcR4GYaTC_gxjNA"

var jwtBadServiceAccount = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJrdWJlcm5ldGVzL3NlcnZpY2VhY2NvdW50Iiwia3ViZXJuZXRlcy5pby9zZXJ2aWNlYWNjb3VudC9uYW1lc3BhY2UiOiJkZWZhdWx0Iiwia3ViZXJuZXRlcy5pby9zZXJ2aWNlYWNjb3VudC9zZWNyZXQubmFtZSI6InZhdWx0LWludmFsaWQtdG9rZW4tZ3ZxcHQiLCJrdWJlcm5ldGVzLmlvL3NlcnZpY2VhY2NvdW50L3NlcnZpY2UtYWNjb3VudC5uYW1lIjoidmF1bHQtaW52YWxpZCIsImt1YmVybmV0ZXMuaW8vc2VydmljZWFjY291bnQvc2VydmljZS1hY2NvdW50LnVpZCI6IjA0NGZkNGYxLTk3NGQtMTFlNy05YTE1LTA4MDAyNzZkOTliZiIsInN1YiI6InN5c3RlbTpzZXJ2aWNlYWNjb3VudDpkZWZhdWx0OnZhdWx0LWludmFsaWQifQ.BcoOdu5BrIchp66Zl8-dY7HcGHJrVXrUh4SNTlIHR6vDaNH29B7JuI_-B1pvW9GpzQnc-XjZyua_wfSssqe-KYJcq--Qh0yQfbbLE5rvEipBCHH341IqGaTHaBVip8zXqYE-bt-7J6vAH8Azvw46iatDC73tKxh46xDuxK0gKjdprW4cOklDx6ZSxEHpu63ftLYgAgk9c0MUJxKWhu9Jk0aye5pTj_iyBbBy8llZNGaw2gxvhPzFVUEHZUlTRiSIbmPmNqep48RiJoWrq6FM1lijvrtT5y-E7aFk6TpW2BH3VDHy8k10sMIxuRAYrGB3tpUKNyVDI3tJOi_xY7iJvw"

var jwtWithBadSigningKey = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJrdWJlcm5ldGVzL3NlcnZpY2VhY2NvdW50Iiwia3ViZXJuZXRlcy5pby9zZXJ2aWNlYWNjb3VudC9uYW1lc3BhY2UiOiJkZWZhdWx0Iiwia3ViZXJuZXRlcy5pby9zZXJ2aWNlYWNjb3VudC9zZWNyZXQubmFtZSI6InZhdWx0LWludmFsaWQtdG9rZW4tZ3ZxcHQiLCJrdWJlcm5ldGVzLmlvL3NlcnZpY2VhY2NvdW50L3NlcnZpY2UtYWNjb3VudC5uYW1lIjoidmF1bHQtYXV0aCIsImt1YmVybmV0ZXMuaW8vc2VydmljZWFjY291bnQvc2VydmljZS1hY2NvdW50LnVpZCI6IjA0NGZkNGYxLTk3NGQtMTFlNy05YTE1LTA4MDAyNzZkOTliZiIsInN1YiI6InN5c3RlbTpzZXJ2aWNlYWNjb3VudDpkZWZhdWx0OnZhdWx0LWF1dGgifQ.hv4O-T9XPtV3Smy55TrA2qCjRJJEQqeifqzbV1kyb8hr7o7kSqhBRy0fSWHi8rkrnBXjibB0yTDDHR1UvkHLWD2Ddi9tKeXZahaKLxGh5GJI8TSxZizX3ilZB9A5LBpW_VberSxcazhGA1u3VEPaL_nPsxWcdF9kxZR3hwSlyEA"

var jwtECDSASigned = "eyJhbGciOiJFUzM4NCIsInR5cCI6IkpXVCIsImtpZCI6ImlUcVhYSTB6YkFuSkNLRGFvYmZoa00xZi02ck1TcFRmeVpNUnBfMnRLSTgifQ.eyJrdWJlcm5ldGVzLmlvL3NlcnZpY2VhY2NvdW50L25hbWVzcGFjZSI6ImRlZmF1bHQiLCJrdWJlcm5ldGVzLmlvL3NlcnZpY2VhY2NvdW50L3NlcnZpY2UtYWNjb3VudC5uYW1lIjoidmF1bHQtYXV0aCIsImt1YmVybmV0ZXMuaW8vc2VydmljZWFjY291bnQvc2VydmljZS1hY2NvdW50LnVpZCI6ImQ3N2Y4OWJjLTkwNTUtMTFlNy1hMDY4LTA4MDAyNzZkOTliZiIsInN1YiI6InN5c3RlbTpzZXJ2aWNlYWNjb3VudDpkZWZhdWx0OnZhdWx0LWF1dGgiLCJpc3MiOiJrdWJlcm5ldGVzL3NlcnZpY2VhY2NvdW50In0.JYxQVgAJQhEIa1lIZ1s9SQ4IrW3FUsl7IfykYBflTgHz0CExAe5BcJ90g1eErVi1RZB1mh2pl9SjIrfFgDeRwqOYwZ4tqCr5dhcZAX5F7yt_RBuuVOvX-EGAklMo0usp"

var ecdsaKey = `-----BEGIN PUBLIC KEY-----
MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEC1uWSXj2czCDwMTLWV5BFmwxdM6PX9p+
Pk9Yf9rIf374m5XP1U8q79dBhLSIuaojsvOT39UUcPJROSD1FqYLued0rXiooIii
1D3jaW6pmGVJFhodzC31cy5sfOYotrzF
-----END PUBLIC KEY-----`

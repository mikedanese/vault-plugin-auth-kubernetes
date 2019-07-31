package kubeauth

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"

	authv1 "k8s.io/api/authentication/v1"
	kubeerrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"

	cleanhttp "github.com/hashicorp/go-cleanhttp"
)

// This is the result from the token review
type tokenReviewResult struct {
	Name      string
	Namespace string
	UID       string
}

// This exists so we can use a mock TokenReview when running tests
type tokenReviewer interface {
	Review(tr *authv1.TokenReview) (*authv1.TokenReview, error)
}

type tokenReviewFactory func(*kubeConfig) tokenReviewer

// This is the real implementation that calls the kubernetes API
type tokenReviewAPI struct {
	config *kubeConfig
}

func tokenReviewAPIFactory(config *kubeConfig) tokenReviewer {
	return &tokenReviewAPI{
		config: config,
	}
}

func LegacyReview(t tokenReviewer, jwt string) (*tokenReviewResult, error) {
	r, err := t.Review(&authv1.TokenReview{
		Spec: authv1.TokenReviewSpec{
			Token: jwt,
		},
	})
	if err != nil {
		return nil, err
	}

	// The username is of format: system:serviceaccount:(NAMESPACE):(SERVICEACCOUNT)
	parts := strings.Split(r.Status.User.Username, ":")
	if len(parts) != 4 {
		return nil, errors.New("lookup failed: unexpected username format")
	}

	// Validate the user that comes back from token review is a service account
	if parts[0] != "system" || parts[1] != "serviceaccount" {
		return nil, errors.New("lookup failed: username returned is not a service account")
	}

	return &tokenReviewResult{
		Name:      parts[3],
		Namespace: parts[2],
		UID:       string(r.Status.User.UID),
	}, nil
}

func (t *tokenReviewAPI) Review(tr *authv1.TokenReview) (*authv1.TokenReview, error) {
	client := cleanhttp.DefaultClient()

	// If we have a CA cert build the TLSConfig
	if len(t.config.CACert) > 0 {
		certPool := x509.NewCertPool()
		certPool.AppendCertsFromPEM([]byte(t.config.CACert))

		tlsConfig := &tls.Config{
			MinVersion: tls.VersionTLS12,
			RootCAs:    certPool,
		}

		client.Transport.(*http.Transport).TLSClientConfig = tlsConfig
	}

	trJSON, err := json.Marshal(tr)
	if err != nil {
		return nil, err
	}

	// Build the request to the token review API
	url := fmt.Sprintf("%s/apis/authentication.k8s.io/v1/tokenreviews", t.config.Host)
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(trJSON))
	if err != nil {
		return nil, err
	}

	// If we have a configured TokenReviewer JWT use it as the bearer, otherwise
	// try to use the passed in JWT.
	bearer := fmt.Sprintf("Bearer %s", tr.Spec.Token)
	if len(t.config.TokenReviewerJWT) > 0 {
		bearer = fmt.Sprintf("Bearer %s", t.config.TokenReviewerJWT)
	}
	bearer = strings.TrimSpace(bearer)

	// Set the JWT as the Bearer token
	req.Header.Set("Authorization", bearer)

	// Set the MIME type headers
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}

	// Parse the resp into a tokenreview object or a kubernetes error type
	tr, err = parseResponse(resp)
	switch {
	case kubeerrors.IsUnauthorized(err):
		// If the err is unauthorized that means the token has since been deleted;
		// this can happen if the service account is deleted, and even if it has
		// since been recreated the token will have changed, which means our
		// caller will need to be updated accordingly.
		return nil, errors.New("lookup failed: service account unauthorized; this could mean it has been deleted or recreated with a new token")
	case err != nil:
		return nil, err
	}

	if tr.Status.Error != "" {
		return nil, fmt.Errorf("lookup failed: %s", tr.Status.Error)
	}

	if !tr.Status.Authenticated {
		return nil, errors.New("lookup failed: service account jwt not valid")
	}
	return tr, nil
}

// parseResponse takes the API response and either returns the appropriate error
// or the TokenReview Object.
func parseResponse(resp *http.Response) (*authv1.TokenReview, error) {
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// If the request was not a success create a kuberenets error
	if resp.StatusCode < http.StatusOK || resp.StatusCode > http.StatusPartialContent {
		return nil, kubeerrors.NewGenericServerResponse(resp.StatusCode, "POST", schema.GroupResource{}, "", strings.TrimSpace(string(body)), 0, true)
	}

	// If we can succesfully Unmarshal into a status object that means there is
	// an error to return
	errStatus := &metav1.Status{}
	err = json.Unmarshal(body, errStatus)
	if err == nil && errStatus.Status != metav1.StatusSuccess {
		return nil, kubeerrors.FromObject(runtime.Object(errStatus))
	}

	// Unmarshal the resp body into a TokenReview Object
	trResp := &authv1.TokenReview{}
	err = json.Unmarshal(body, trResp)
	if err != nil {
		return nil, err
	}

	return trResp, nil
}

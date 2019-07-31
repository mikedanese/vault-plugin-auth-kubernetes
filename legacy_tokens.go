package kubeauth

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"errors"
	"fmt"

	"github.com/briankassouf/jose/crypto"
	"github.com/briankassouf/jose/jws"
	"github.com/briankassouf/jose/jwt"
	"github.com/mitchellh/mapstructure"

	"github.com/hashicorp/errwrap"
	multierror "github.com/hashicorp/go-multierror"
	"github.com/hashicorp/vault/sdk/logical"
)

var (
	// expectedJWTIssuer is used to verify the iss header on the JWT.
	expectedJWTIssuer = "kubernetes/serviceaccount"

	uidJWTClaimKey = "kubernetes.io/serviceaccount/service-account.uid"

	// errMismatchedSigningMethod is used if the certificate doesn't match the
	// JWT's expected signing method.
	errMismatchedSigningMethod = errors.New("invalid signing method")
)

func authenticateLegacy(jwtStr string, pubKeys []interface{}, tr tokenReviewer) (*logical.Auth, error) {
	serviceAccount, err := parseAndValidateJWT(jwtStr, pubKeys)
	if err != nil {
		return nil, err
	}

	// look up the JWT token in the kubernetes API
	err = serviceAccount.lookup(jwtStr, tr)
	if err != nil {
		return nil, err
	}

	return &logical.Auth{
		Alias: &logical.Alias{
			Name: serviceAccount.UID,
			Metadata: map[string]string{
				"service_account_uid":         serviceAccount.UID,
				"service_account_name":        serviceAccount.Name,
				"service_account_namespace":   serviceAccount.Namespace,
				"service_account_secret_name": serviceAccount.SecretName,
			},
		},
		Metadata: map[string]string{
			"service_account_uid":         serviceAccount.UID,
			"service_account_name":        serviceAccount.Name,
			"service_account_namespace":   serviceAccount.Namespace,
			"service_account_secret_name": serviceAccount.SecretName,
		},
		DisplayName: fmt.Sprintf("%s-%s", serviceAccount.Namespace, serviceAccount.Name),
	}, nil
}

// parseAndValidateJWT is used to parse, validate and lookup the JWT token.
func parseAndValidateJWT(jwtStr string, pubKeys []interface{}) (*serviceAccount, error) {
	// Parse into JWT
	parsedJWT, err := jws.ParseJWT([]byte(jwtStr))
	if err != nil {
		return nil, err
	}

	sa := &serviceAccount{}
	validator := &jwt.Validator{
		Expected: jwt.Claims{
			"iss": expectedJWTIssuer,
		},
		Fn: func(c jwt.Claims) error {
			// Decode claims into a service account object
			return mapstructure.Decode(c, sa)
		},
	}

	if err := validator.Validate(parsedJWT); err != nil {
		return nil, err
	}

	// If we don't have any public keys to verify, return the sa and end early.
	if len(pubKeys) == 0 {
		return sa, nil
	}

	// verifyFunc is called for each certificate that is configured in the
	// backend until one of the certificates succeeds.
	verifyFunc := func(cert interface{}) error {
		// Parse Headers and verify the signing method matches the public key type
		// configured. This is done in its own scope since we don't need most of
		// these variables later.
		var signingMethod crypto.SigningMethod
		{
			parsedJWS, err := jws.Parse([]byte(jwtStr))
			if err != nil {
				return err
			}
			headers := parsedJWS.Protected()

			var algStr string
			if headers.Has("alg") {
				algStr = headers.Get("alg").(string)
			} else {
				return errors.New("provided JWT must have 'alg' header value")
			}

			signingMethod = jws.GetSigningMethod(algStr)
			switch signingMethod.(type) {
			case *crypto.SigningMethodECDSA:
				if _, ok := cert.(*ecdsa.PublicKey); !ok {
					return errMismatchedSigningMethod
				}
			case *crypto.SigningMethodRSA:
				if _, ok := cert.(*rsa.PublicKey); !ok {
					return errMismatchedSigningMethod
				}
			default:
				return errors.New("unsupported JWT signing method")
			}
		}

		// validates the signature and then runs the claim validation
		if err := parsedJWT.Validate(cert, signingMethod); err != nil {
			return err
		}

		return nil
	}

	var validationErr error
	// for each configured certificate run the verifyFunc
	for _, cert := range pubKeys {
		err := verifyFunc(cert)
		switch err {
		case nil:
			return sa, nil
		case rsa.ErrVerification, crypto.ErrECDSAVerification, errMismatchedSigningMethod:
			// if the error is a failure to verify or a signing method mismatch
			// continue onto the next cert, storing the error to be returned if
			// this is the last cert.
			validationErr = multierror.Append(validationErr, errwrap.Wrapf("failed to validate JWT: {{err}}", err))
			continue
		default:
			return nil, err
		}
	}

	return nil, validationErr
}

// serviceAccount holds the metadata from the JWT token and is used to lookup
// the JWT in the kubernetes API and compare the results.
type serviceAccount struct {
	Name       string `mapstructure:"kubernetes.io/serviceaccount/service-account.name"`
	UID        string `mapstructure:"kubernetes.io/serviceaccount/service-account.uid"`
	SecretName string `mapstructure:"kubernetes.io/serviceaccount/secret.name"`
	Namespace  string `mapstructure:"kubernetes.io/serviceaccount/namespace"`
}

// lookup calls the TokenReview API in kubernetes to verify the token and secret
// still exist.
func (s *serviceAccount) lookup(jwtStr string, tr tokenReviewer) error {
	r, err := LegacyReview(tr, jwtStr)
	if err != nil {
		return err
	}

	// Verify the returned metadata matches the expected data from the service
	// account.
	if s.Name != r.Name {
		return errors.New("JWT names did not match")
	}
	if s.UID != r.UID {
		return errors.New("JWT UIDs did not match")
	}
	if s.Namespace != r.Namespace {
		return errors.New("JWT namepaces did not match")
	}

	return nil
}

package v1alpha1

import (
	"context"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/Keyurendra/shadowtest/api/v1alpha1"
)

func validateArtifactToken(ctx context.Context, c client.Reader, tkn v1alpha1.ArtifactAPIToken, ns string) *field.Error {
	tknPath := field.NewPath("spec").Child("artifactAPI").Child("token").Child("secretRef")
	secretRef := tkn.SecretRef

	var secret corev1.Secret
	key := types.NamespacedName{Namespace: ns, Name: secretRef.Name}

	if err := c.Get(ctx, key, &secret); err != nil {
		if apierrors.IsNotFound(err) {
			return field.NotFound(tknPath.Child("name"), secretRef.Name)
		}
		return field.InternalError(
			tknPath.Child("name"),
			fmt.Errorf("failed to get secret: %w", err),
		)
	}

	tknByts, ok := secret.Data[secretRef.Key]
	if !ok {
		return field.NotFound(tknPath.Child("key"), secretRef.Key)
	}

	parser := jwt.NewParser(jwt.WithoutClaimsValidation())
	jwtTkn, _, err := parser.ParseUnverified(string(tknByts), jwt.MapClaims{})
	if err != nil {
		return field.Invalid(
			tknPath,
			"<redacted>",
			fmt.Sprintf("jwt token is invalid: %v", err),
		)
	}
	if jwtTkn == nil {
		return field.Invalid(tknPath, "<redacted>", "jwt token is invalid")
	}

	exp, err := jwtTkn.Claims.GetExpirationTime()
	if err != nil {
		return field.InternalError(
			tknPath,
			fmt.Errorf("failed to get exp from JWT: %w", err),
		)
	}
	if exp != nil && exp.Before(time.Now()) {
		return field.Invalid(tknPath, "<redacted>", "jwt token has expired")
	}

	nb, err := jwtTkn.Claims.GetNotBefore()
	if err != nil {
		return field.InternalError(
			tknPath,
			fmt.Errorf("failed to get NotBefore field from JWT: %w", err),
		)
	}
	if nb != nil && nb.After(time.Now()) {
		return field.Invalid(tknPath, "<redacted>", "jwt token is not valid yet")
	}

	return nil
}

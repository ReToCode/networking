package kncertreconciler

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrs "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	listerv1 "k8s.io/client-go/listers/core/v1"
	"knative.dev/networking/pkg/apis/networking/v1alpha1"
	"knative.dev/networking/pkg/certificates"
	"knative.dev/networking/pkg/certificates/kncertreconciler/resources"
	certreconciler "knative.dev/networking/pkg/client/injection/reconciler/networking/v1alpha1/certificate"
	"knative.dev/pkg/controller"
	"knative.dev/pkg/logging"
	pkgreconciler "knative.dev/pkg/reconciler"
	"knative.dev/pkg/system"
)

const (
	notReconciledReason  = "ReconcileFailed"
	notReconciledMessage = "KnativeCertificate has not yet been reconciled."

	createdEventReason        = "Created"
	creationFailedEventReason = "CreationFailed"

	updatedEventReason      = "Updated"
	updateFailedEventReason = "UpdateFailed"

	expirationInterval = time.Hour * 24 * 90 // 90 days (aligned with Let's encrypt)
	rotationThreshold  = time.Hour * 24 * 30 // 30 days (aligned with Let's encrypt)
)

// Reconciler implements controller.Reconciler for Knative Certificate resources.
type reconciler struct {
	client       kubernetes.Interface
	caSecretName string
	labelName    string
	secretLister listerv1.SecretLister
	enqueueAfter func(key types.NamespacedName, delay time.Duration)
}

// Check that our Reconciler implements certreconciler.Interface
var _ certreconciler.Interface = (*reconciler)(nil)

func (r *reconciler) ReconcileKind(ctx context.Context, knCert *v1alpha1.Certificate) pkgreconciler.Event {
	ctx, cancel := context.WithTimeout(ctx, pkgreconciler.DefaultTimeout)
	defer cancel()

	// Reconcile the KnativeCertificate and then write back any status
	// updates regardless of whether the reconciliation errored out.
	err := r.reconcile(ctx, knCert)
	if err != nil {
		if knCert.Status.GetCondition(v1alpha1.CertificateConditionReady).Status != corev1.ConditionFalse {
			knCert.Status.MarkNotReady(notReconciledReason, notReconciledMessage)
		}
	}
	return err
}

func (r *reconciler) reconcile(ctx context.Context, knCert *v1alpha1.Certificate) error {
	logger := logging.FromContext(ctx)
	recorder := controller.GetEventRecorder(ctx)

	knCert.SetDefaults(ctx)
	knCert.Status.InitializeConditions()
	knCert.Status.ObservedGeneration = knCert.Generation

	logger.Info("Reconciling KnativeCertificate with Knatives internal certificate issuer.")

	// Get and parse CA
	caSecret, err := r.client.CoreV1().Secrets(system.Namespace()).Get(ctx, r.caSecretName, metav1.GetOptions{})
	if err != nil {
		msg := fmt.Sprintf("failed to create certificate %s/%s. The CA does not yet exist.", knCert.Namespace, knCert.Name)
		recorder.Eventf(knCert, corev1.EventTypeWarning, creationFailedEventReason, msg)
		return fmt.Errorf(msg+" error: %w", err)
	}
	caCert, caKey, err := parseCertFromSecret(caSecret)
	if err != nil {
		msg := fmt.Sprintf("failed to create certificate %s/%s. The CA is invalid.", knCert.Namespace, knCert.Name)
		recorder.Eventf(knCert, corev1.EventTypeWarning, creationFailedEventReason, msg)
		return fmt.Errorf(msg+" error: %w", err)
	}

	// Create the desired secret
	desiredCert, err := certificates.CreateCert(caKey, caCert, expirationInterval, knCert.Spec.DNSNames...)
	if err != nil {
		msg := fmt.Sprintf("failed to create desired certificate %s/%s.", knCert.Namespace, knCert.Name)
		recorder.Eventf(knCert, corev1.EventTypeWarning, creationFailedEventReason, msg)
		return fmt.Errorf(msg+" error: %w", err)
	}

	desiredSecret := resources.MakeSecret(knCert, desiredCert, caSecret.Data[certificates.CertName], r.labelName)

	// Create/Update secret for KnativeCertificate
	existingCertSecret, err := r.secretLister.Secrets(knCert.Namespace).Get(knCert.Spec.SecretName)
	if apierrs.IsNotFound(err) {
		newCertSecret, err := r.client.CoreV1().Secrets(knCert.Namespace).Create(ctx, desiredSecret, metav1.CreateOptions{})
		if err != nil {
			msg := fmt.Sprintf("failed to create secret %s/%s.", desiredSecret.Namespace, desiredSecret.Name)
			recorder.Eventf(knCert, corev1.EventTypeWarning, creationFailedEventReason, msg)
			return fmt.Errorf(msg+" error: %w", err)
		}

		recorder.Eventf(newCertSecret, corev1.EventTypeNormal, createdEventReason,
			"Created certificate in secret %s/%s for KnativeCertificate %s/%s",
			newCertSecret.Namespace, newCertSecret.Name, knCert.Namespace, knCert.Name)

		if err = r.enqueueBeforeExpiration(newCertSecret); err != nil {
			return err
		}

	} else if err != nil {
		msg := fmt.Sprintf("failed to get existing secret %s/%s.", knCert.Namespace, knCert.Spec.SecretName)
		recorder.Eventf(knCert, corev1.EventTypeWarning, creationFailedEventReason, msg)
		return fmt.Errorf(msg+" error: %w", err)
	} else {
		updateCert := false
		existingCert, _, err := parseCertFromSecret(existingCertSecret)
		if err != nil {
			recorder.Eventf(knCert, corev1.EventTypeWarning, updatedEventReason,
				"The existing certificate in secret %s/%s is invalid. It will be replaced by a new one.",
				existingCertSecret.Namespace, existingCertSecret.Name)
			updateCert = true
		}

		if err := certificates.CheckExpiry(existingCert, rotationThreshold); err != nil {
			recorder.Eventf(knCert, corev1.EventTypeNormal, updatedEventReason,
				"Certificate for KnativeCertificate %s/%s is above the rotation threshold of %v days. It will be renewed.",
				knCert.Namespace, knCert.Name, rotationThreshold)
			updateCert = true
		}

		if updateCert {
			// Don't modify the informer copy.
			secret := existingCertSecret.DeepCopy()
			secret.Annotations = desiredSecret.Annotations
			secret.Labels = desiredSecret.Labels
			secret.Data = desiredSecret.Data

			updatedCertSecret, err := r.client.CoreV1().Secrets(secret.Namespace).Update(ctx, secret, metav1.UpdateOptions{})
			if err != nil {
				msg := fmt.Sprintf("failed to update existing secret %s/%s.", secret.Namespace, secret.Name)
				recorder.Eventf(knCert, corev1.EventTypeWarning, updateFailedEventReason, msg)
				return fmt.Errorf(msg+" error: %w", err)
			}

			recorder.Eventf(knCert, corev1.EventTypeNormal, updatedEventReason,
				"Successfully updated certificate in secret %s/%s for KnativeCertificate %s/%s",
				secret.Namespace, secret.Name, knCert.Namespace, knCert.Name)

			if err = r.enqueueBeforeExpiration(updatedCertSecret); err != nil {
				return err
			}
		} else {
			if err = r.enqueueBeforeExpiration(existingCertSecret); err != nil {
				return err
			}
		}

		return nil
	}

	return nil
}

func (r *reconciler) enqueueBeforeExpiration(secret *corev1.Secret) error {
	cert, _, err := parseCertFromSecret(secret)
	if err != nil {
		return err
	}

	// Enqueue after the rotation threshold
	when := cert.NotAfter.Add(-rotationThreshold).Add(1 * time.Second)
	r.enqueueAfter(types.NamespacedName{
		Namespace: secret.Namespace,
		Name:      secret.Name,
	}, time.Until(when))

	return nil
}

func parseCertFromSecret(secret *corev1.Secret) (*x509.Certificate, *rsa.PrivateKey, error) {
	certBytes, ok := secret.Data[certificates.CertName]
	if !ok {
		return nil, nil, fmt.Errorf("missing cert bytes")
	}
	pkBytes, ok := secret.Data[certificates.PrivateKeyName]
	if !ok {
		return nil, nil, fmt.Errorf("missing pk bytes")
	}

	cert, caPk, err := certificates.ParseCert(certBytes, pkBytes)
	if err != nil {
		return nil, nil, err
	}

	return cert, caPk, nil
}

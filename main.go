package main

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"time"

	"git.dolansoft.org/dolansoft/k8s-generic-secrets/apis/dolansoft.org/v1beta1"
	clientset "git.dolansoft.org/dolansoft/k8s-generic-secrets/generated/clientset/versioned"
	informers "git.dolansoft.org/dolansoft/k8s-generic-secrets/generated/informers/externalversions"
	"git.dolansoft.org/dolansoft/k8s-generic-secrets/jsonpatch"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/klog/v2"
	"maze.io/x/duration"
)

const (
	tokenLength  = 16 // 128 bit secure
	fieldManager = "k8s-generic-secrets"
)

var (
	// From RFC 5280 Section 4.1.2.5
	unknownNotAfter = time.Unix(253402300799, 0)
)

var (
	masterURL = flag.String("master", "",
		"The address of the Kubernetes API server. Overrides any value in kubeconfig. Only required if out-of-cluster.")
	kubeconfig = flag.String("kubeconfig", "",
		"Path to a kubeconfig. Only required if out-of-cluster.")
	clusterDomain = flag.String("cluster-domain", "cluster.local", "Kubernetes DNS cluster domain (default cluster.local)")
)

type controller struct {
	kclient  *kubernetes.Clientset
	dsclient *clientset.Clientset
	queue    workqueue.RateLimitingInterface
}

func (c *controller) enqueueSC(obj interface{}) {
	key, err := cache.MetaNamespaceKeyFunc(obj)
	if err != nil {
		panic(err)
	}
	c.queue.Add(key)
}

// processQueueItems gets items from the given work queue and calls the process function for each of them. It self-
// terminates once the queue is shut down.
func (c *controller) processQueueItems(queue workqueue.RateLimitingInterface, process func(key string) error) {
	for {
		obj, shutdown := queue.Get()
		if shutdown {
			return
		}

		func(obj interface{}) {
			defer queue.Done(obj)
			key, ok := obj.(string)
			if !ok {
				queue.Forget(obj)
				log.Printf("Expected string in workqueue, got %+v", obj)
				return
			}

			if err := process(key); err != nil {
				log.Printf("Failed processing item \"%v\", requeueing (%v tries): %v", key, queue.NumRequeues(obj), err)
				queue.AddRateLimited(obj)
			}

			queue.Forget(obj)
		}(obj)
	}
}

func (c *controller) certFromSecret(ctx context.Context, namespace string, name string) (*x509.Certificate, crypto.PrivateKey, error) {
	caSecret, err := c.kclient.CoreV1().Secrets(namespace).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get caSecret: %w", err)
	}
	caCertPEM := caSecret.Data["ca.crt"]
	caCertBlock, _ := pem.Decode(caCertPEM)
	if caCertBlock == nil {
		return nil, nil, fmt.Errorf("\"ca.crt\" contains no PEM data in secret \"%s\": %w", name, err)
	}
	caCert, err := x509.ParseCertificate(caCertBlock.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse \"ca.crt\" certificate: %w", err)
	}
	caKeyPEM := caSecret.Data["ca.key"]
	caKeyBlock, _ := pem.Decode(caKeyPEM)
	if caCertBlock == nil {
		return nil, nil, fmt.Errorf("\"ca.key\" contains no PEM data in secret \"%s\": %w", name, err)
	}
	var caKey crypto.PrivateKey
	if caKeyBlock.Type == "EC PRIVATE KEY" {
		caKey, err = x509.ParseECPrivateKey(caKeyBlock.Bytes)
	} else if caKeyBlock.Type == "PRIVATE KEY" {
		caKey, err = x509.ParsePKCS8PrivateKey(caKeyBlock.Bytes)
	} else {
		return nil, nil, fmt.Errorf("unknown PEM block type \"%s\" in private key", caKeyBlock.Type)
	}
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse \"ca.key\" key: %w", err)
	}
	return caCert, caKey, nil
}

func (c *controller) issueCertificate(ctx context.Context, claim *v1beta1.SecretClaim, data map[string][]byte) error {
	x509spec := claim.Spec.X509Claim
	var commonName string = x509spec.CommonName
	if commonName == "" {
		commonName = claim.Name
	}
	var notAfter time.Time = unknownNotAfter
	if x509spec.RotateEvery != "" {
		d, err := duration.ParseDuration(x509spec.RotateEvery)
		if err != nil {
			return fmt.Errorf("cannot parse rotateEvery duration: %w", err)
		}
		notAfter = time.Now().Add(time.Duration(d))
	}
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 127)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return fmt.Errorf("failed to generate serial number: %v", err)
	}

	var keyUsage x509.KeyUsage = x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment
	if x509spec.IsCA {
		keyUsage = x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature
	}

	eku := []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth}
	if x509spec.IsCA {
		eku = nil
	}

	var dnsNames []string
	for _, svc := range x509spec.ServiceNames {
		dnsNames = append(dnsNames, svc, svc+"."+claim.Namespace, svc+"."+claim.Namespace+".svc."+*clusterDomain)
	}
	for _, extraName := range x509spec.ExtraNames {
		dnsNames = append(dnsNames, extraName)
	}

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: commonName,
		},
		NotBefore:             time.Now(),
		NotAfter:              notAfter,
		BasicConstraintsValid: true,
		IsCA:                  x509spec.IsCA,
		KeyUsage:              keyUsage,
		ExtKeyUsage:           eku,
		DNSNames:              dnsNames,
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("failed to generate key: %w", err)
	}

	var certRaw []byte

	if x509spec.CASecretName == "" {
		certRaw, err = x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
		if err != nil {
			return fmt.Errorf("failed to sign certificate: %w", err)
		}
	} else {
		caCert, caKey, err := c.certFromSecret(ctx, claim.Namespace, x509spec.CASecretName)
		if err != nil {
			return err
		}
		certRaw, err = x509.CreateCertificate(rand.Reader, template, caCert, &key.PublicKey, caKey)
		if err != nil {
			return fmt.Errorf("failed to sign certificate: %w", err)
		}
	}

	var keyRaw []byte
	var keyType string
	if x509spec.LegacySEC1PrivateKey {
		keyRaw, err = x509.MarshalECPrivateKey(key)
		keyType = "EC PRIVATE KEY"
	} else {
		keyRaw, err = x509.MarshalPKCS8PrivateKey(key)
		keyType = "PRIVATE KEY"
	}
	if err != nil {
		return fmt.Errorf("cannot marshal EC private key: %w", err)
	}

	if x509spec.IsCA {
		data["ca.crt"] = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certRaw})
		data["ca.key"] = pem.EncodeToMemory(&pem.Block{Type: keyType, Bytes: keyRaw})
	} else {
		data["tls.crt"] = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certRaw})
		data["tls.key"] = pem.EncodeToMemory(&pem.Block{Type: keyType, Bytes: keyRaw})
	}
	return nil
}

func (c *controller) reconcileSC(key string) error {
	namespace, name, err := cache.SplitMetaNamespaceKey(key)
	if err != nil {
		panic(err)
	}
	ctx := context.Background()
	sc, err := c.dsclient.DolansoftV1beta1().SecretClaims(namespace).Get(context.Background(), name, metav1.GetOptions{})
	if errors.IsNotFound(err) {
		return nil // Nothing to reconcile
	}
	if err != nil {
		return err
	}
	oldSecret, err := c.kclient.CoreV1().Secrets(namespace).Get(ctx, name, metav1.GetOptions{})
	if errors.IsNotFound(err) {
		newData := make(map[string][]byte)
		if sc.Spec.X509Claim != nil {
			if err := c.issueCertificate(ctx, sc, newData); err != nil {
				return fmt.Errorf("failed to issue certificate: %w", err)
			}
		} else {
			for k, v := range sc.Spec.FixedFields {
				newData[k] = []byte(v)
			}
			for _, field := range sc.Spec.TokenFields {
				newToken := make([]byte, tokenLength)
				if _, err := io.ReadFull(rand.Reader, newToken); err != nil {
					return fmt.Errorf("failed to read randomness: %w", err)
				}
				newData[field] = []byte(hex.EncodeToString(newToken))
			}
		}
		newSecret := corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:            name,
				Namespace:       namespace,
				OwnerReferences: []metav1.OwnerReference{*metav1.NewControllerRef(sc, schema.GroupVersionKind{Group: v1beta1.GroupName, Kind: v1beta1.Kind, Version: v1beta1.Version})},
			},
			Data: newData,
		}
		if _, err := c.kclient.CoreV1().Secrets(namespace).Create(ctx, &newSecret, metav1.CreateOptions{FieldManager: fieldManager}); err != nil {
			return fmt.Errorf("failed to create new secret: %w", err)
		}
		return nil
	}
	if err != nil {
		return err
	}
	if sc.Spec.X509Claim != nil {
		// TODO(lorenz): Implement reconciliation for X.509
		return nil
	}
	newData := make(map[string][]byte)
	for k, v := range sc.Spec.FixedFields {
		if !bytes.Equal(oldSecret.Data[k], []byte(v)) {
			newData[k] = []byte(v)
		}
	}
	for _, field := range sc.Spec.TokenFields {
		_, ok := oldSecret.Data[field]
		if !ok {
			newToken := make([]byte, tokenLength)
			if _, err := io.ReadFull(rand.Reader, newToken); err != nil {
				return fmt.Errorf("failed to read randomness: %w", err)
			}
			newData[field] = []byte(hex.EncodeToString(newToken))
		}
	}
	if len(newData) > 0 {
		var patchOps []jsonpatch.JsonPatchOp
		for k, v := range newData {
			patchOps = append(patchOps, jsonpatch.JsonPatchOp{
				Operation: "add",
				Path:      jsonpatch.PointerFromParts([]string{"data", k}),
				Value:     base64.StdEncoding.EncodeToString(v),
			})
		}
		patch, err := json.Marshal(patchOps)
		if err != nil {
			panic(err)
		}
		if _, err := c.kclient.CoreV1().Secrets(namespace).Patch(ctx, name, types.JSONPatchType, patch, metav1.PatchOptions{FieldManager: fieldManager}); err != nil {
			return fmt.Errorf("failed to patch secret: %w", err)
		}
	}
	return nil
}

func main() {
	flag.Parse()

	cfg, err := clientcmd.BuildConfigFromFlags(*masterURL, *kubeconfig)
	if err != nil {
		klog.Fatalf("Error building kubeconfig: %s", err.Error())
	}

	kubeClient, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		klog.Fatalf("Error building kubernetes clientset: %s", err.Error())
	}

	dsClient, err := clientset.NewForConfig(cfg)
	if err != nil {
		klog.Fatalf("Error building example clientset: %s", err.Error())
	}

	dsInformerFactory := informers.NewSharedInformerFactory(dsClient, time.Minute*5)
	scClient := dsInformerFactory.Dolansoft().V1beta1().SecretClaims()
	ctrl := controller{
		kclient:  kubeClient,
		dsclient: dsClient,
		queue:    workqueue.NewRateLimitingQueue(workqueue.DefaultControllerRateLimiter()),
	}
	scClient.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			ctrl.enqueueSC(obj)
		},
		UpdateFunc: func(oldObj, newObj interface{}) {
			ctrl.enqueueSC(newObj)
		},
		DeleteFunc: func(obj interface{}) {
			// K8s GC automatically cleans up after us
		},
	})
	go ctrl.processQueueItems(ctrl.queue, func(key string) error {
		return ctrl.reconcileSC(key)
	})
	scClient.Informer().Run(make(<-chan struct{}))
}

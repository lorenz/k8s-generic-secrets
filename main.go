package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
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
)

const (
	tokenLength  = 16 // 128 bit secure
	fieldManager = "k8s-generic-secrets"
)

var (
	masterURL = flag.String("master", "",
		"The address of the Kubernetes API server. Overrides any value in kubeconfig. Only required if out-of-cluster.")
	kubeconfig = flag.String("kubeconfig", "",
		"Path to a kubeconfig. Only required if out-of-cluster.")
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

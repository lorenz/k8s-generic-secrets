// Code generated by client-gen. DO NOT EDIT.

package v1beta1

import (
	"context"
	"time"

	v1beta1 "git.dolansoft.org/dolansoft/k8s-generic-secrets/apis/dolansoft.org/v1beta1"
	scheme "git.dolansoft.org/dolansoft/k8s-generic-secrets/generated/clientset/versioned/scheme"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	types "k8s.io/apimachinery/pkg/types"
	watch "k8s.io/apimachinery/pkg/watch"
	rest "k8s.io/client-go/rest"
)

// SecretClaimsGetter has a method to return a SecretClaimInterface.
// A group's client should implement this interface.
type SecretClaimsGetter interface {
	SecretClaims(namespace string) SecretClaimInterface
}

// SecretClaimInterface has methods to work with SecretClaim resources.
type SecretClaimInterface interface {
	Create(ctx context.Context, secretClaim *v1beta1.SecretClaim, opts v1.CreateOptions) (*v1beta1.SecretClaim, error)
	Update(ctx context.Context, secretClaim *v1beta1.SecretClaim, opts v1.UpdateOptions) (*v1beta1.SecretClaim, error)
	UpdateStatus(ctx context.Context, secretClaim *v1beta1.SecretClaim, opts v1.UpdateOptions) (*v1beta1.SecretClaim, error)
	Delete(ctx context.Context, name string, opts v1.DeleteOptions) error
	DeleteCollection(ctx context.Context, opts v1.DeleteOptions, listOpts v1.ListOptions) error
	Get(ctx context.Context, name string, opts v1.GetOptions) (*v1beta1.SecretClaim, error)
	List(ctx context.Context, opts v1.ListOptions) (*v1beta1.SecretClaimList, error)
	Watch(ctx context.Context, opts v1.ListOptions) (watch.Interface, error)
	Patch(ctx context.Context, name string, pt types.PatchType, data []byte, opts v1.PatchOptions, subresources ...string) (result *v1beta1.SecretClaim, err error)
	SecretClaimExpansion
}

// secretClaims implements SecretClaimInterface
type secretClaims struct {
	client rest.Interface
	ns     string
}

// newSecretClaims returns a SecretClaims
func newSecretClaims(c *DolansoftV1beta1Client, namespace string) *secretClaims {
	return &secretClaims{
		client: c.RESTClient(),
		ns:     namespace,
	}
}

// Get takes name of the secretClaim, and returns the corresponding secretClaim object, and an error if there is any.
func (c *secretClaims) Get(ctx context.Context, name string, options v1.GetOptions) (result *v1beta1.SecretClaim, err error) {
	result = &v1beta1.SecretClaim{}
	err = c.client.Get().
		Namespace(c.ns).
		Resource("secretclaims").
		Name(name).
		VersionedParams(&options, scheme.ParameterCodec).
		Do(ctx).
		Into(result)
	return
}

// List takes label and field selectors, and returns the list of SecretClaims that match those selectors.
func (c *secretClaims) List(ctx context.Context, opts v1.ListOptions) (result *v1beta1.SecretClaimList, err error) {
	var timeout time.Duration
	if opts.TimeoutSeconds != nil {
		timeout = time.Duration(*opts.TimeoutSeconds) * time.Second
	}
	result = &v1beta1.SecretClaimList{}
	err = c.client.Get().
		Namespace(c.ns).
		Resource("secretclaims").
		VersionedParams(&opts, scheme.ParameterCodec).
		Timeout(timeout).
		Do(ctx).
		Into(result)
	return
}

// Watch returns a watch.Interface that watches the requested secretClaims.
func (c *secretClaims) Watch(ctx context.Context, opts v1.ListOptions) (watch.Interface, error) {
	var timeout time.Duration
	if opts.TimeoutSeconds != nil {
		timeout = time.Duration(*opts.TimeoutSeconds) * time.Second
	}
	opts.Watch = true
	return c.client.Get().
		Namespace(c.ns).
		Resource("secretclaims").
		VersionedParams(&opts, scheme.ParameterCodec).
		Timeout(timeout).
		Watch(ctx)
}

// Create takes the representation of a secretClaim and creates it.  Returns the server's representation of the secretClaim, and an error, if there is any.
func (c *secretClaims) Create(ctx context.Context, secretClaim *v1beta1.SecretClaim, opts v1.CreateOptions) (result *v1beta1.SecretClaim, err error) {
	result = &v1beta1.SecretClaim{}
	err = c.client.Post().
		Namespace(c.ns).
		Resource("secretclaims").
		VersionedParams(&opts, scheme.ParameterCodec).
		Body(secretClaim).
		Do(ctx).
		Into(result)
	return
}

// Update takes the representation of a secretClaim and updates it. Returns the server's representation of the secretClaim, and an error, if there is any.
func (c *secretClaims) Update(ctx context.Context, secretClaim *v1beta1.SecretClaim, opts v1.UpdateOptions) (result *v1beta1.SecretClaim, err error) {
	result = &v1beta1.SecretClaim{}
	err = c.client.Put().
		Namespace(c.ns).
		Resource("secretclaims").
		Name(secretClaim.Name).
		VersionedParams(&opts, scheme.ParameterCodec).
		Body(secretClaim).
		Do(ctx).
		Into(result)
	return
}

// UpdateStatus was generated because the type contains a Status member.
// Add a +genclient:noStatus comment above the type to avoid generating UpdateStatus().
func (c *secretClaims) UpdateStatus(ctx context.Context, secretClaim *v1beta1.SecretClaim, opts v1.UpdateOptions) (result *v1beta1.SecretClaim, err error) {
	result = &v1beta1.SecretClaim{}
	err = c.client.Put().
		Namespace(c.ns).
		Resource("secretclaims").
		Name(secretClaim.Name).
		SubResource("status").
		VersionedParams(&opts, scheme.ParameterCodec).
		Body(secretClaim).
		Do(ctx).
		Into(result)
	return
}

// Delete takes name of the secretClaim and deletes it. Returns an error if one occurs.
func (c *secretClaims) Delete(ctx context.Context, name string, opts v1.DeleteOptions) error {
	return c.client.Delete().
		Namespace(c.ns).
		Resource("secretclaims").
		Name(name).
		Body(&opts).
		Do(ctx).
		Error()
}

// DeleteCollection deletes a collection of objects.
func (c *secretClaims) DeleteCollection(ctx context.Context, opts v1.DeleteOptions, listOpts v1.ListOptions) error {
	var timeout time.Duration
	if listOpts.TimeoutSeconds != nil {
		timeout = time.Duration(*listOpts.TimeoutSeconds) * time.Second
	}
	return c.client.Delete().
		Namespace(c.ns).
		Resource("secretclaims").
		VersionedParams(&listOpts, scheme.ParameterCodec).
		Timeout(timeout).
		Body(&opts).
		Do(ctx).
		Error()
}

// Patch applies the patch and returns the patched secretClaim.
func (c *secretClaims) Patch(ctx context.Context, name string, pt types.PatchType, data []byte, opts v1.PatchOptions, subresources ...string) (result *v1beta1.SecretClaim, err error) {
	result = &v1beta1.SecretClaim{}
	err = c.client.Patch(pt).
		Namespace(c.ns).
		Resource("secretclaims").
		Name(name).
		SubResource(subresources...).
		VersionedParams(&opts, scheme.ParameterCodec).
		Body(data).
		Do(ctx).
		Into(result)
	return
}

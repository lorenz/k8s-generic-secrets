# Kubernetes Generic Secrets

## Users Guide

This creates and maintains a secret in the same namespace as a secret claim. It automatically
generates 128-bit secure hex-encoded tokens and keeps them for the lifetime of the secret. You can
delete the secret if you need to rotate the tokens, it will be recreated.

The following is a quite minimal example claim:

```yaml
apiVersion: dolansoft.org/v1beta1
kind: SecretClaim
metadata:
  name: hello
spec:
  tokenFields:
    - keytothekingdom
  fixedFields:
    hello: world
```

It will result in the generation of a secret similar to this one:

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: hello
type: Opaque
data:
  hello: d29ybGQ= # world
  keytothekingdom: OGU4MDliNjk4MDNkMzkyMjg1YWVlZGUxYWU3ZWUyOWI= # 8e809b69803d392285aeede1ae7ee29b
```

Secrets will be automatically cleaned up when the claim is deleted.

### X509 claims

_Experimental, no reconciliation yet_

It can also maintain an X.509-based PKI for use with mTLS or client certificates.

```yaml
apiVersion: dolansoft.org/v1beta1
kind: SecretClaim
metadata:
  name: hello-ca
spec:
  x509:
    isCA: true
  # Indefinitely-valid CA, with Subject: CN = hello-ca stored as PEM in ca.crt with P256 key in ca.key
apiVersion: dolansoft.org/v1beta1
kind: SecretClaim
metadata:
  name: hello-client1
spec:
  x509:
    caSecretName: hello-ca
  # Indefinitely-valid client certificate with CN = hello-client1

apiVersion: dolansoft.org/v1beta1
kind: SecretClaim
metadata:
  name: hello-svc
spec:
  x509:
    caSecretName: hello-ca
    serviceNames:
      - hello
  # Indefinitely-valid client certificate with CN = hello-svc and SANs hello, hello.<namespace>
  # hello.<namespace>.svc.cluster.local
```

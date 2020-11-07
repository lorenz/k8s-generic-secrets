# Kubernetes Generic Secrets

## Users Guide
This creates and maintains a secret in the same namespace as a secret claim. It automatically generates 128-bit secure hex-encoded tokens and keeps them for the lifetime of the secret. You can delete the secret if you need to rotate the tokens, it will be recreated.

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
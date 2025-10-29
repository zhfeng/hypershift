---
title: "Bound Token Signing Keypair Management"
weight: 350
description: "Comprehensive guide to managing bound service account token signing keypairs in HyperShift"
---

# Bound Token Signing Keypair Management

This guide provides comprehensive documentation for managing bound service account token signing keypairs in HyperShift clusters.

## Overview

### What are Bound Tokens?

Bound tokens are JSON Web Tokens (JWT) issued by the kube-apiserver via the TokenRequest API. Unlike traditional service account tokens, bound tokens have the following characteristics:

- **Time-bound**: They expire automatically and cannot be manually revoked
- **Audience-specific**: They are validated only for specific audiences
- **Cryptographically signed**: They use RSA keypairs for signature validation
- **Secure**: The private key never leaves the control plane

### How HyperShift Uses Bound Tokens

HyperShift implements bound token management through several components:

1. **Token Minter**: Creates bound tokens for service-to-service communication
2. **HostedCluster API**: Configures signing keypairs and issuer URLs
3. **Service Account Utilities**: Manages token lifecycle with audience support
4. **Platform Integration**: Automatically manages OIDC discovery (AWS, Azure)

## Architecture

### TokenRequest API Flow

```
┌─────────────────┐    TokenRequest    ┌──────────────────┐
│ Service Account │ ──────────────────► │ Kube-apiserver   │
│ (tenant cluster) │                   │ (control plane)  │
└─────────────────┘                   └──────────────────┘
                                              │
                                              │ Signs with RSA
                                              │ Private Key
                                              ▼
                                    ┌──────────────────┐
                                    │ Bound JWT Token  │
                                    │ (expires, bound) │
                                    └──────────────────┘
```

### RSA Keypair Management

The bound token signing keypair is managed as follows:

- **Private Key**: Stored in `openshift-kube-apiserver-operator/next-bound-service-account-signing-key` secret
- **Public Keys**: Distributed via `openshift-config-managed/bound-sa-token-signing-certs` configmap
- **Key Rotation**: Manual process with 2-phase rollout for compatibility
- **Public Key Accumulation**: All public keys are retained to ensure token validity during rotation

### HyperShift Implementation Details

#### Token Minter Component

The token minter (`/token-minter/tokenminter.go`) handles:

- Token creation using TokenRequest API
- Automatic token refresh before expiry
- Support for multiple audiences (openshift, issuer-specific)
- Error handling and retry logic

#### HostedCluster Configuration

The HostedCluster API provides these fields for bound token configuration:

```yaml
apiVersion: hypershift.openshift.io/v1beta1
kind: HostedCluster
spec:
  platform:
    type: AWS  # or Azure, etc.
  oidcProviders:
  - issuerURL: https://your-oidc-provider.com
    serviceAccountSigningKey:
      name: my-signing-key-secret
```

## Configuration

### Prerequisites

Before configuring bound token signing:

1. **Issuer URL**: Required when using custom signing keys
2. **RSA Key Pair**: Generate a suitable RSA key pair (2048-bit minimum)
3. **Secret Access**: Permissions to create secrets in the service cluster
4. **Platform Access**: S3 bucket access for AWS, etc.

### ServiceAccountSigningKey Configuration

#### Generate RSA Key Pair

```bash
# Generate private key
openssl genrsa -out signing-key.pem 2048

# Generate public key
openssl rsa -in signing-key.pem -pubout -out signing-key-pub.pem

# Create secret in service cluster
kubectl create secret generic my-signing-key-secret \
  --from-file=service-account-signing-key=signing-key.pem \
  --from-file=service-account-signing-key-pub=signing-key-pub.pem \
  -n clusters
```

#### Configure HostedCluster

```yaml
apiVersion: hypershift.openshift.io/v1beta1
kind: HostedCluster
metadata:
  name: my-cluster
  namespace: clusters
spec:
  platform:
    type: AWS
  oidcProviders:
  - issuerURL: https://oidc.example.com
    serviceAccountSigningKey:
      name: my-signing-key-secret
```

### Platform-Specific Configuration

#### AWS Integration

HyperShift automatically uploads OIDC discovery documents to S3:

```yaml
apiVersion: hypershift.openshift.io/v1beta1
kind: HostedCluster
metadata:
  name: my-cluster
spec:
  platform:
    aws:
      endpointAccess: Public
      s3:
        bucketName: my-oidc-bucket
  oidcProviders:
  - issuerURL: https://oidc.example.com
    serviceAccountSigningKey:
      name: my-signing-key-secret
```

#### Azure Workload Identity

For Azure workload identity integration:

```yaml
apiVersion: hypershift.openshift.io/v1beta1
kind: HostedCluster
spec:
  platform:
    azure:
      location: eastus
      resourceGroupName: my-rg
  oidcProviders:
  - issuerURL: https://sts.windows.net/{tenant-id}/
    serviceAccountSigningKey:
      name: my-signing-key-secret
```

## Key Management

### Key Generation Guidelines

#### RSA Key Requirements

- **Key Size**: 2048-bit minimum, 4096-bit recommended for high-security environments
- **Algorithm**: RSA with SHA-256 (RS256)
- **Format**: PEM-encoded
- **Expiration**: RSA keys do not expire (unlike certificates)

#### Security Best Practices

1. **Secure Storage**: Private keys should never leave the control plane
2. **Access Control**: Limit access to signing key secrets
3. **Backup Strategy**: Maintain secure backups of private keys
4. **Key Rotation**: Rotate keys only if compromise is suspected
5. **Monitoring**: Audit access to signing key secrets

### Manual Key Rotation

#### Rotation Process

Key rotation is a manual 2-phase process to ensure compatibility:

```bash
# Phase 1: Delete next signing key to trigger rotation
kubectl delete secret next-bound-service-account-signing-key \
  -n openshift-kube-apiserver-operator

# Wait for first rollout (distributes new public key)
kubectl wait --for=condition=Progressing=False \
  deployment/kube-apiserver -n openshift-kube-apiserver

# Phase 2: Wait for second rollout (activates new private key)
# This happens automatically after first rollout completes
```

#### Rollout Timeline

- **Single Rollout**: Up to 20 minutes
- **Complete Rotation**: Up to 40 minutes (2 rollouts)
- **Token Validity**: Existing tokens remain valid until natural expiry

#### Emergency Rotation (Nuclear Option)

If you need to invalidate all existing bound tokens immediately:

```bash
# WARNING: This will break all workloads using bound tokens
# Delete signing secret to force rotation
kubectl delete secret bound-service-account-signing-key \
  -n openshift-kube-apiserver

# Remove public key configmap to invalidate previous tokens
kubectl delete configmap bound-sa-token-signing-certs \
  -n openshift-config-managed

# Restart all pods to refresh tokens
kubectl delete pods --all -n your-workload-namespace
```

## Third-Party Integration

### Public Key Consumption

Third-party systems can validate bound tokens by:

1. **Watching ConfigMap**: Monitor `openshift-config-managed/bound-sa-token-signing-certs`
2. **OIDC Discovery**: Use the well-known OIDC discovery endpoint
3. **Direct API Access**: Query the Kubernetes API for public keys

#### ConfigMap Structure

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: bound-sa-token-signing-certs
  namespace: openshift-config-managed
data:
  service-account-key-1.pem: |
    -----BEGIN PUBLIC KEY-----
    MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA...
    -----END PUBLIC KEY-----
  service-account-key-2.pem: |
    -----BEGIN PUBLIC KEY-----
    MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA...
    -----END PUBLIC KEY-----
```

#### Python Validation Example

```python
import jwt
import requests
from kubernetes import client, config

def validate_bound_token(token):
    """Validate a bound service account token"""

    # Load Kubernetes config
    config.load_incluster_config()
    v1 = client.CoreV1Api()

    # Get public keys from configmap
    cm = v1.read_namespaced_config_map(
        "bound-sa-token-signing-certs",
        "openshift-config-managed"
    )

    # Try each public key
    for key_name, key_data in cm.data.items():
        try:
            # Decode and validate token
            decoded = jwt.decode(
                token,
                key_data,
                algorithms=["RS256"],
                audience="your-expected-audience"
            )
            return decoded
        except jwt.InvalidTokenError:
            continue

    raise ValueError("Token validation failed with all keys")
```

#### Go Validation Example

```go
package main

import (
    "context"
    "fmt"
    "k8s.io/client-go/kubernetes"
    "github.com/golang-jwt/jwt/v4"
)

func ValidateBoundToken(tokenString string) (*jwt.Token, error) {
    // Create Kubernetes client
    config, err := rest.InClusterConfig()
    if err != nil {
        return nil, err
    }

    clientset, err := kubernetes.NewForConfig(config)
    if err != nil {
        return nil, err
    }

    // Get public keys
    cm, err := clientset.CoreV1().ConfigMaps("openshift-config-managed").
        Get(context.TODO(), "bound-sa-token-signing-certs", metav1.GetOptions{})
    if err != nil {
        return nil, err
    }

    // Try each public key
    for keyName, keyData := range cm.Data {
        publicKey, err := jwt.ParseRSAPublicKeyFromPEM([]byte(keyData))
        if err != nil {
            continue
        }

        token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
            return publicKey, nil
        })

        if err == nil && token.Valid {
            return token, nil
        }
    }

    return nil, fmt.Errorf("token validation failed")
}
```

### OIDC Discovery Endpoint

HyperShift provides OIDC discovery at:

```
https://<cluster-api-url>/discovery/1.0
```

#### Discovery Response

```json
{
  "issuer": "https://oidc.example.com",
  "jwks_uri": "https://<cluster-api-url>/openid/v1/jwks",
  "response_types_supported": ["id_token"],
  "subject_types_supported": ["public"],
  "id_token_signing_alg_values_supported": ["RS256"]
}
```

#### JWKS Response

```json
{
  "keys": [
    {
      "kty": "RSA",
      "kid": "key-1",
      "use": "sig",
      "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
      "e": "AQAB"
    }
  ]
}
```

## Operations

### Monitoring and Observability

#### Key Metrics to Monitor

1. **Token Creation Rate**: Success/failure rates from token minter
2. **Token Expiry**: Monitor token refresh patterns
3. **API Server Latency**: Token validation performance
4. **Secret Access**: Auditing of signing key secret access

#### Prometheus Metrics

```yaml
# Token creation metrics
hypershift_token_minter_tokens_created_total
hypershift_token_minter_token_creation_errors_total
hypershift_token_minter_token_refresh_total

# API server metrics
apiserver_request_duration_seconds{resource="serviceaccounts", verb="create"}
apiserver_request_total{resource="tokenreviews"}
```

#### Alerting Rules

```yaml
groups:
- name: hypershift-bound-tokens
  rules:
  - alert: BoundTokenCreationHighFailureRate
    expr: rate(hypershift_token_minter_token_creation_errors_total[5m]) > 0.1
    for: 5m
    labels:
      severity: warning
    annotations:
      summary: "High bound token creation failure rate"

  - alert: BoundTokenExpiryImminent
    expr: hypershift_token_minter_tokens_expiring_soon > 0
    for: 10m
    labels:
      severity: critical
    annotations:
      summary: "Bound tokens expiring soon"
```

### Troubleshooting

#### Common Issues

##### Token Validation Fails

**Symptoms**: Third-party systems cannot validate tokens

**Causes**:
- Public key configmap not updated
- Incorrect audience in token
- Network connectivity issues

**Solutions**:
```bash
# Check public key configmap
kubectl get configmap bound-sa-token-signing-certs \
  -n openshift-config-managed -o yaml

# Verify audience in token
echo "eyJ..." | base64 -d | jq '.aud'

# Check network connectivity
curl -k https://<cluster-api-url>/openid/v1/jwks
```

##### Token Minter Errors

**Symptoms**: Token minter pod shows errors

**Causes**:
- Invalid signing key secret
- Missing issuer URL
- Permission issues

**Solutions**:
```bash
# Check token minter logs
kubectl logs -n hypershift deployment/token-minter

# Verify signing key secret
kubectl get secret <signing-key-secret> -n clusters -o yaml

# Check HostedCluster configuration
kubectl get hostedcluster <cluster-name> -o yaml
```

##### Rotation Issues

**Symptoms**: Key rotation stuck or incomplete

**Causes**:
- API server rollout failures
- Missing public key distribution
- Manual intervention required

**Solutions**:
```bash
# Check API server rollout status
kubectl rollout status deployment/kube-apiserver \
  -n openshift-kube-apiserver

# Verify public key distribution
kubectl get configmap bound-sa-token-signing-certs \
  -n openshift-config-managed

# Force manual rotation if needed
kubectl delete secret next-bound-service-account-signing-key \
  -n openshift-kube-apiserver-operator
```

#### Debug Commands

```bash
# Get current signing key info
kubectl get secret bound-service-account-signing-key \
  -n openshift-kube-apiserver -o yaml

# Check public key accumulation
kubectl get configmap bound-sa-token-signing-certs \
  -n openshift-config-managed -o jsonpath='{.data.*}' | wc -l

# Monitor token creation
kubectl logs -f -n hypershift deployment/token-minter | grep token

# Validate OIDC discovery
curl -k https://<cluster-api-url>/discovery/1.0 | jq .
```

### Performance Considerations

#### Token Validation Performance

- **Key Cache**: Public keys are cached in API servers
- **Validation Cost**: RSA signature verification is CPU-intensive
- **Network Calls**: Third-party validation requires API server access

#### Optimization Strategies

1. **Local Key Caching**: Cache public keys locally in third-party systems
2. **Batch Validation**: Validate multiple tokens in single request
3. **Connection Pooling**: Reuse HTTP connections for OIDC discovery
4. **Key Rotation Planning**: Schedule rotations during low-traffic periods

#### Resource Requirements

- **CPU**: Additional CPU for RSA signature verification
- **Memory**: Public key storage in API servers
- **Network**: Bandwidth for OIDC discovery requests
- **Storage**: Configmap storage for accumulated public keys

## Security Considerations

### Access Control

#### RBAC Requirements

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  namespace: clusters
  name: bound-token-manager
rules:
- apiGroups: [""]
  resources: ["secrets"]
  resourceNames: ["my-signing-key-secret"]
  verbs: ["get", "list", "watch"]
- apiGroups: ["hypershift.openshift.io"]
  resources: ["hostedclusters"]
  verbs: ["get", "list", "watch", "patch"]
```

#### Secret Access Control

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: my-signing-key-secret
  namespace: clusters
  annotations:
    hypershift.openshift.io/signing-key: "true"
type: Opaque
data:
  service-account-signing-key: <base64-encoded-private-key>
  service-account-signing-key-pub: <base64-encoded-public-key>
```

### Audit Logging

#### Enable Token Audit Logging

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: audit-policy
  namespace: openshift-kube-apiserver
data:
  policy.yaml: |
    apiVersion: audit.k8s.io/v1
    kind: Policy
    rules:
    - level: Metadata
      resources:
      - group: ""
        resources: ["serviceaccounts"]
      verbs: ["create"]
    - level: Request
      resources:
      - group: ""
        resources: ["serviceaccounts/token"]
      verbs: ["create"]
```

#### Monitoring Audit Logs

```bash
# Check token creation audit logs
kubectl logs -n openshift-kube-apiserver deployment/kube-apiserver | \
  grep "serviceaccounts/token" | tail -10

# Monitor secret access
kubectl get events -n clusters --field-selector reason="Pulled"
```

### Compliance and Governance

#### Key Rotation Requirements

- **Document all rotations**: Maintain audit trail of key changes
- **Emergency procedures**: Document nuclear option procedures
- **Backup verification**: Regularly test key backup and restore procedures
- **Access reviews**: Periodic review of secret access permissions

#### Third-Party Validation

- **Document integrations**: Maintain inventory of systems validating tokens
- **SLA agreements**: Define availability requirements for OIDC endpoints
- **Testing procedures**: Regular testing of third-party validation workflows
- **Incident response**: Plan for OIDC endpoint failures

## Advanced Topics

### Multi-Cluster Token Validation

For multi-cluster environments, consider:

1. **Shared Keypairs**: Use same signing key across clusters
2. **Cross-Cluster Trust**: Configure trust relationships between clusters
3. **Central Validation**: Centralized token validation service
4. **Key Synchronization**: Automated key distribution across clusters

### Custom Token Audiences

HyperShift supports custom token audiences:

```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: my-service-account
  namespace: default
---
apiVersion: v1
kind: Secret
metadata:
  name: my-service-account-token
  annotations:
    kubernetes.io/service-account.name: my-service-account
type: kubernetes.io/service-account-token
```

```go
// Create token with custom audience
tokenRequest := &authenticationv1.TokenRequest{
  Spec: authenticationv1.TokenRequestSpec{
    Audiences: []string{"my-custom-audience"},
    ExpirationSeconds: &[]int64{3600}[0],
  },
}

token, err := clientset.CoreV1().ServiceAccounts("default").
  CreateToken(context.TODO(), "my-service-account", tokenRequest, metav1.CreateOptions{})
```

### Integration with External OIDC Providers

For integration with external OIDC providers:

1. **Issuer URL Configuration**: Set appropriate issuer URL
2. **Key Discovery**: Configure key discovery from external provider
3. **Token Mapping**: Map external tokens to internal service accounts
4. **Federation**: Configure token federation between systems

## Migration Guide

### From Traditional Service Account Tokens

When migrating from traditional tokens to bound tokens:

1. **Identify Usage**: Find all current token usage
2. **Update Applications**: Modify applications to use TokenRequest API
3. **Token Refresh**: Implement automatic token refresh
4. **Rollback Plan**: Plan for rollback if issues occur

### Migration Checklist

- [ ] Audit current token usage
- [ ] Update application code for token refresh
- [ ] Configure ServiceAccountSigningKey
- [ ] Test token validation workflows
- [ ] Update monitoring and alerting
- [ ] Document migration procedures
- [ ] Plan rollback procedures

## References

### External Documentation

- [Kubernetes TokenRequest API](https://kubernetes.io/docs/reference/kubernetes-api/authentication-resources/token-request-v1/)
- [OpenID Connect Discovery](https://openid.net/specs/openid-connect-discovery-1_0.html)
- [JWT Specification](https://tools.ietf.org/html/rfc7519)
- [RS256 Algorithm](https://tools.ietf.org/html/rfc7518#section-3.3)

### HyperShift Documentation

- [HostedCluster API Reference](../hostedcluster/)
- [Authentication Overview](../authentication/)
- [Security Best Practices](../security/)
- [Monitoring and Observability](../monitoring/)

### Code References

- [Token Minter Implementation](https://github.com/openshift/hypershift/tree/main/token-minter)
- [HostedCluster API Types](https://github.com/openshift/hypershift/tree/main/api/hypershift/v1beta1)
- [Service Account Utilities](https://github.com/openshift/hypershift/tree/main/support/util)
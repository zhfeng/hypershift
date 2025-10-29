---
title: "Set Up Bound Token Authentication"
weight: 100
description: "Step-by-step guide to configure bound service account token authentication in HyperShift"
---

# Set Up Bound Token Authentication

This guide provides step-by-step instructions for configuring bound service account token authentication in HyperShift clusters.

## Prerequisites

Before you begin, ensure you have:

- **HyperShift CLI** (`hypershift`) installed
- **kubectl** configured with access to the service cluster
- **Permissions** to create secrets and configure HostedClusters
- **RSA key generation tools** (OpenSSL)
- **Platform access** (AWS S3 bucket, Azure subscription, etc.)

## Quick Start

### 1. Generate RSA Key Pair

```bash
# Create a directory for keys
mkdir -p ~/hypershift-keys
cd ~/hypershift-keys

# Generate 2048-bit RSA private key
openssl genrsa -out service-account-signing-key.pem 2048

# Extract public key
openssl rsa -in service-account-signing-key.pem -pubout -out service-account-signing-key-pub.pem

# Verify the keys
openssl rsa -in service-account-signing-key.pem -check
openssl rsa -pubin -in service-account-signing-key-pub.pem -text -noout
```

### 2. Create Secret in Service Cluster

```bash
# Create secret in the clusters namespace
kubectl create secret generic my-bound-token-signing-key \
  --from-file=service-account-signing-key=service-account-signing-key.pem \
  --from-file=service-account-signing-key-pub=service-account-signing-key-pub.pem \
  -n clusters

# Verify the secret
kubectl get secret my-bound-token-signing-key -n clusters -o yaml
```

### 3. Configure HostedCluster

```yaml
# hosted-cluster-with-bound-tokens.yaml
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
      name: my-bound-token-signing-key
```

```bash
# Create the HostedCluster
kubectl apply -f hosted-cluster-with-bound-tokens.yaml
```

## Platform-Specific Setup

### AWS Setup

#### Prerequisites

- **AWS CLI** configured with appropriate permissions
- **S3 bucket** for OIDC discovery documents
- **Route53 hosted zone** (optional, for custom domain)

#### Step 1: Create S3 Bucket

```bash
# Create S3 bucket
aws s3 mb s3://my-oidc-discovery-bucket --region us-east-1

# Set bucket policy for public read access
cat > bucket-policy.json << EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "PublicReadGetObject",
      "Effect": "Allow",
      "Principal": "*",
      "Action": "s3:GetObject",
      "Resource": "arn:aws:s3:::my-oidc-discovery-bucket/*"
    }
  ]
}
EOF

aws s3api put-bucket-policy \
  --bucket my-oidc-discovery-bucket \
  --policy file://bucket-policy.json
```

#### Step 2: Configure HostedCluster for AWS

```yaml
# aws-hosted-cluster.yaml
apiVersion: hypershift.openshift.io/v1beta1
kind: HostedCluster
metadata:
  name: my-aws-cluster
  namespace: clusters
spec:
  platform:
    aws:
      region: us-east-1
      endpointAccess: Public
      s3:
        bucketName: my-oidc-discovery-bucket
  oidcProviders:
  - issuerURL: https://my-oidc-discovery-bucket.s3.us-east-1.amazonaws.com
    serviceAccountSigningKey:
      name: my-bound-token-signing-key
  networking:
    networkType: OVNKubernetes
    serviceNetwork:
      - 172.31.0.0/16
  dns:
    baseDomain: my-domain.com
```

```bash
# Deploy the cluster
kubectl apply -f aws-hosted-cluster.yaml
```

#### Step 3: Verify OIDC Discovery

```bash
# Wait for cluster to be ready
kubectl wait hostedcluster my-aws-cluster --for=condition=Available --timeout=20m

# Test OIDC discovery endpoint
curl -s https://my-oidc-discovery-bucket.s3.us-east-1.amazonaws.com/discovery/1.0 | jq .
```

### Azure Setup

#### Prerequisites

- **Azure CLI** logged in with appropriate permissions
- **Resource group** for HyperShift resources
- **Azure AD application** (optional, for advanced scenarios)

#### Step 1: Set up Azure Resources

```bash
# Variables
RESOURCE_GROUP="my-hypershift-rg"
LOCATION="eastus"

# Create resource group
az group create --name $RESOURCE_GROUP --location $LOCATION
```

#### Step 2: Configure HostedCluster for Azure

```yaml
# azure-hosted-cluster.yaml
apiVersion: hypershift.openshift.io/v1beta1
kind: HostedCluster
metadata:
  name: my-azure-cluster
  namespace: clusters
spec:
  platform:
    azure:
      location: eastus
      resourceGroupName: $RESOURCE_GROUP
      networkResourceGroupName: $RESOURCE_GROUP
      virtualNetwork: my-hypershift-vnet
      controlPlaneSubnet: my-hypershift-cp-subnet
      computeSubnet: my-hypershift-compute-subnet
  oidcProviders:
  - issuerURL: https://sts.windows.net/${TENANT_ID}/
    serviceAccountSigningKey:
      name: my-bound-token-signing-key
  networking:
    networkType: OVNKubernetes
    serviceNetwork:
      - 172.31.0.0/16
  dns:
    baseDomain: my-domain.com
```

```bash
# Get tenant ID
TENANT_ID=$(az account show --query tenantId -o tsv)

# Deploy the cluster
kubectl apply -f azure-hosted-cluster.yaml
```

#### Step 3: Configure Azure Workload Identity

```bash
# Enable Azure Workload Identity
hypershift create cluster azure \
  --name my-azure-cluster \
  --namespace clusters \
  --azure-location eastus \
  --azure-tenant-id $TENANT_ID \
  --azure-resource-group $RESOURCE_GROUP \
  --oidc-issuer-url https://sts.windows.net/$TENANT_ID/ \
  --service-account-signing-key-secret my-bound-token-signing-key
```

### Generic Setup (No Platform)

For on-premises or generic cloud setups:

```yaml
# generic-hosted-cluster.yaml
apiVersion: hypershift.openshift.io/v1beta1
kind: HostedCluster
metadata:
  name: my-generic-cluster
  namespace: clusters
spec:
  platform:
    type: None
  oidcProviders:
  - issuerURL: https://oidc.my-company.com
    serviceAccountSigningKey:
      name: my-bound-token-signing-key
  networking:
    networkType: OVNKubernetes
    serviceNetwork:
      - 172.31.0.0/16
  dns:
    baseDomain: my-local-domain.com
```

## Advanced Configuration

### Multiple OIDC Providers

```yaml
apiVersion: hypershift.openshift.io/v1beta1
kind: HostedCluster
metadata:
  name: my-multi-oidc-cluster
spec:
  oidcProviders:
  - issuerURL: https://primary-oidc.example.com
    serviceAccountSigningKey:
      name: primary-signing-key
  - issuerURL: https://secondary-oidc.example.com
    serviceAccountSigningKey:
      name: secondary-signing-key
```

### Custom Audiences

```bash
# Create service account with custom audiences
cat > custom-audience-sa.yaml << EOF
apiVersion: v1
kind: ServiceAccount
metadata:
  name: my-service
  namespace: default
---
apiVersion: v1
kind: Secret
metadata:
  name: my-service-token
  annotations:
    kubernetes.io/service-account.name: my-service
    kubernetes.io/service-account.token.expiration: "3600"
type: kubernetes.io/service-account-token
EOF

kubectl apply -f custom-audience-sa.yaml
```

### Key Rotation Setup

```bash
#!/bin/bash
# rotate-bound-token-keys.sh

set -e

CLUSTER_NAME="my-cluster"
NAMESPACE="clusters"
NEW_KEY_SECRET="new-signing-key-$(date +%Y%m%d)"

echo "Starting bound token key rotation for $CLUSTER_NAME"

# 1. Generate new key pair
echo "Generating new RSA key pair..."
mkdir -p /tmp/key-rotation
cd /tmp/key-rotation

openssl genrsa -out new-service-account-signing-key.pem 2048
openssl rsa -in new-service-account-signing-key.pem -pubout -out new-service-account-signing-key-pub.pem

# 2. Create new secret
echo "Creating new signing key secret..."
kubectl create secret generic $NEW_KEY_SECRET \
  --from-file=service-account-signing-key=new-service-account-signing-key.pem \
  --from-file=service-account-signing-key-pub=new-service-account-signing-key-pub.pem \
  -n $NAMESPACE

# 3. Update HostedCluster to use new key
echo "Updating HostedCluster configuration..."
kubectl patch hostedcluster $CLUSTER_NAME -n $NAMESPACE \
  --type='merge' \
  -p='{"spec":{"oidcProviders":[{"serviceAccountSigningKey":{"name":"'$NEW_KEY_SECRET'"}}]}}'

# 4. Wait for rollout
echo "Waiting for control plane rollout..."
kubectl wait --for=condition=Progressing=False \
  deployment/kube-apiserver -n openshift-kube-apiserver --timeout=20m

echo "Key rotation completed successfully!"
echo "New signing key: $NEW_KEY_SECRET"
echo "Remember to clean up old keys after validation period."
```

## Validation and Testing

### Test Token Creation

```bash
#!/bin/bash
# test-bound-token.sh

SERVICE_ACCOUNT="default"
NAMESPACE="default"
AUDIENCE="openshift"

echo "Testing bound token creation for service account: $SERVICE_ACCOUNT"

# Create token request
cat > token-request.yaml << EOF
apiVersion: authentication.k8s.io/v1
kind: TokenRequest
metadata:
  name: token-request
spec:
  audiences: [$AUDIENCE]
  expirationSeconds: 3600
EOF

# Create token
TOKEN=$(kubectl create -f token-request.yaml -o jsonpath='{.status.token}')

echo "Token created successfully"
echo "Token: ${TOKEN:0:50}..."

# Decode token (header and payload only)
echo "Token header:"
echo $TOKEN | cut -d. -f1 | base64 -d | jq .

echo "Token payload:"
echo $TOKEN | cut -d. -f2 | base64 -d | jq .
```

### Test Third-Party Validation

```python
#!/usr/bin/env python3
# validate-token.py

import jwt
import requests
import sys
import base64
from kubernetes import client, config

def validate_token_with_public_keys(token, cluster_api_url):
    """Validate token using cluster's public keys"""

    try:
        # Load kubernetes config
        config.load_incluster_config()
        v1 = client.CoreV1()

        # Get public keys from configmap
        cm = v1.read_namespaced_config_map(
            "bound-sa-token-signing-certs",
            "openshift-config-managed"
        )

        # Try each public key
        for key_name, key_data in cm.data.items():
            try:
                decoded = jwt.decode(
                    token,
                    key_data,
                    algorithms=["RS256"],
                    audience="openshift"
                )
                print(f"✅ Token validated successfully with key: {key_name}")
                print(f"   Subject: {decoded.get('sub')}")
                print(f"   Issuer: {decoded.get('iss')}")
                print(f"   Expiration: {decoded.get('exp')}")
                return True

            except jwt.InvalidTokenError as e:
                print(f"❌ Failed validation with key {key_name}: {e}")
                continue

        print("❌ Token validation failed with all keys")
        return False

    except Exception as e:
        print(f"❌ Error during validation: {e}")
        return False

def validate_token_with_oidc_discovery(token, cluster_api_url):
    """Validate token using OIDC discovery"""

    try:
        # Get OIDC discovery document
        discovery_url = f"{cluster_api_url}/discovery/1.0"
        discovery_response = requests.get(discovery_url, verify=False)
        discovery_response.raise_for_status()

        discovery_data = discovery_response.json()
        jwks_url = discovery_data.get('jwks_uri')

        if not jwks_url:
            print("❌ No JWKS URI found in discovery document")
            return False

        # Get JWKS
        jwks_response = requests.get(jwks_url, verify=False)
        jwks_response.raise_for_status()

        jwks_data = jwks_response.json()

        # Validate token
        decoded = jwt.decode(
            token,
            jwks_data,
            algorithms=["RS256"],
            audience="openshift",
            options={"verify_aud": True}
        )

        print(f"✅ Token validated successfully via OIDC discovery")
        print(f"   Subject: {decoded.get('sub')}")
        print(f"   Issuer: {decoded.get('iss')}")
        return True

    except Exception as e:
        print(f"❌ Error during OIDC validation: {e}")
        return False

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python validate-token.py <token> <cluster-api-url>")
        sys.exit(1)

    token = sys.argv[1]
    cluster_api_url = sys.argv[2]

    print(f"Validating token against cluster: {cluster_api_url}")

    # Try public key validation first
    if not validate_token_with_public_keys(token, cluster_api_url):
        # Fallback to OIDC discovery
        validate_token_with_oidc_discovery(token, cluster_api_url)
```

### Test with curl

```bash
#!/bin/bash
# test-token-curl.sh

TOKEN=$(kubectl create token default -n default --duration=10m)
CLUSTER_URL=$(kubectl get hostedcluster my-cluster -o jsonpath='{.status.controlPlaneEndpoint}')

echo "Testing token access to cluster API..."

# Test token with cluster API
curl -k -H "Authorization: Bearer $TOKEN" \
  "$CLUSTER_URL/api/v1/namespaces/default/pods" | jq '.items[0].metadata.name'

# Test OIDC discovery
curl -k "$CLUSTER_URL/discovery/1.0" | jq .

# Test JWKS endpoint
curl -k "$CLUSTER_URL/openid/v1/jwks" | jq .
```

## Monitoring and Troubleshooting

### Check Token Minter Status

```bash
# Check token minter pod
kubectl get pods -n hypershift | grep token-minter

# Check token minter logs
kubectl logs -n hypershift deployment/token-minter -f

# Check token creation metrics
kubectl exec -n hypershift deployment/token-minter -- \
  curl -s http://localhost:8080/metrics | grep token
```

### Validate Configuration

```bash
#!/bin/bash
# validate-configuration.sh

CLUSTER_NAME="my-cluster"
NAMESPACE="clusters"

echo "Validating bound token configuration for $CLUSTER_NAME"

# 1. Check HostedCluster configuration
echo "1. Checking HostedCluster configuration..."
kubectl get hostedcluster $CLUSTER_NAME -n $NAMESPACE -o jsonpath='{.spec.oidcProviders}' | jq .

# 2. Check signing key secret
echo "2. Checking signing key secret..."
SIGNING_KEY_SECRET=$(kubectl get hostedcluster $CLUSTER_NAME -n $NAMESPACE \
  -o jsonpath='{.spec.oidcProviders[0].serviceAccountSigningKey.name}')

kubectl get secret $SIGNING_KEY_SECRET -n $NAMESPACE -o jsonpath='{.data.service-account-signing-key}' | \
  base64 -d | openssl rsa -check -noout

kubectl get secret $SIGNING_KEY_SECRET -n $NAMESPACE -o jsonpath='{.data.service-account-signing-key-pub}' | \
  base64 -d | openssl rsa -pubin -text -noout

# 3. Check public key distribution
echo "3. Checking public key distribution..."
kubectl get configmap bound-sa-token-signing-certs \
  -n openshift-config-managed -o jsonpath='{.data.*}' | wc -l

# 4. Test OIDC discovery
echo "4. Testing OIDC discovery..."
CLUSTER_URL=$(kubectl get hostedcluster $CLUSTER_NAME -n $NAMESPACE \
  -o jsonpath='{.status.controlPlaneEndpoint}')

curl -k -s "$CLUSTER_URL/discovery/1.0" | jq .

echo "Configuration validation completed!"
```

### Common Issues and Solutions

#### Issue: Token Creation Fails

**Error**: `serviceaccounts "default" is forbidden: User "system:serviceaccount:hypershift:token-minter" cannot create resource "serviceaccounts/token"`

**Solution**:
```bash
# Check RBAC permissions
kubectl get rolebinding -n hypershift | grep token-minter

# Create necessary RBAC if missing
cat > token-minter-rbac.yaml << EOF
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  namespace: clusters
  name: bound-token-creator
rules:
- apiGroups: [""]
  resources: ["serviceaccounts"]
  verbs: ["create", "get", "list", "watch"]
- apiGroups: [""]
  resources: ["serviceaccounts/token"]
  verbs: ["create"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: token-minter-bound-token-creator
  namespace: clusters
subjects:
- kind: ServiceAccount
  name: token-minter
  namespace: hypershift
roleRef:
  kind: Role
  name: bound-token-creator
  apiGroup: rbac.authorization.k8s.io
EOF

kubectl apply -f token-minter-rbac.yaml
```

#### Issue: OIDC Discovery Fails

**Error**: `404 Not Found` from discovery endpoint

**Solution**:
```bash
# Check if control plane is ready
kubectl get hostedcluster my-cluster -o yaml | grep -A5 conditions

# Check if OIDC provider is configured
kubectl get hostedcluster my-cluster -o jsonpath='{.spec.oidcProviders}' | jq .

# Restart kube-apiserver if needed
kubectl rollout restart deployment/kube-apiserver -n openshift-kube-apiserver
```

#### Issue: Third-Party Validation Fails

**Error**: `Invalid signature` or `Key not found`

**Solution**:
```bash
# Check public key configmap
kubectl get configmap bound-sa-token-signing-certs \
  -n openshift-config-managed -o yaml

# Verify public key matches private key
PRIVATE_KEY=$(kubectl get secret my-bound-token-signing-key -n clusters \
  -o jsonpath='{.data.service-account-signing-key}' | base64 -d)

PUBLIC_KEY=$(kubectl get secret my-bound-token-signing-key -n clusters \
  -o jsonpath='{.data.service-account-signing-key-pub}' | base64 -d)

# Extract public key from private key and compare
echo "$PRIVATE_KEY" | openssl rsa -pubout -out /tmp/derived-pub.pem

# Compare keys
diff /tmp/derived-pub.pem <(echo "$PUBLIC_KEY")
```

## Migration from Traditional Tokens

### Step-by-Step Migration

```bash
#!/bin/bash
# migrate-to-bound-tokens.sh

set -e

CLUSTER_NAME="my-cluster"
NAMESPACE="clusters"
BACKUP_DIR="/tmp/token-migration-$(date +%Y%m%d)"

echo "Starting migration to bound tokens for $CLUSTER_NAME"

# 1. Create backup directory
mkdir -p $BACKUP_DIR

# 2. Identify existing service account token usage
echo "2. Identifying existing token usage..."
kubectl get serviceaccounts --all-namespaces -o wide > $BACKUP_DIR/service-accounts.txt
kubectl get secrets --all-namespaces --field-selector type=kubernetes.io/service-account-token > $BACKUP_DIR/sa-tokens.txt

# 3. Create new signing key
echo "3. Creating new bound token signing key..."
./generate-signing-key.sh

# 4. Update HostedCluster configuration
echo "4. Updating HostedCluster configuration..."
kubectl patch hostedcluster $CLUSTER_NAME -n $NAMESPACE \
  --type='merge' \
  -p='{"spec":{"oidcProviders":[{"serviceAccountSigningKey":{"name":"my-bound-token-signing-key"}}]}}'

# 5. Wait for rollout
echo "5. Waiting for control plane rollout..."
kubectl wait --for=condition=Available hostedcluster $CLUSTER_NAME -n $NAMESPACE --timeout=20m

# 6. Test bound token creation
echo "6. Testing bound token creation..."
BOUND_TOKEN=$(kubectl create token default -n default --duration=1h)
echo "Created bound token: ${BOUND_TOKEN:0:50}..."

# 7. Validate configuration
echo "7. Validating configuration..."
./validate-configuration.sh

echo "Migration completed successfully!"
echo "Backup files saved to: $BACKUP_DIR"
echo "Remember to update your applications to use bound tokens."
```

### Update Application Code

#### Before (Traditional Token)

```python
from kubernetes import client, config

# Traditional service account token
config.load_incluster_config()
v1 = client.CoreV1API()

# Get token from secret
token_secret = v1.read_namespaced_secret("my-app-token", "default")
token = base64.b64decode(token_secret.data["token"]).decode()
```

#### After (Bound Token)

```python
from kubernetes import client, config
import time

class BoundTokenManager:
    def __init__(self):
        config.load_incluster_config()
        self.v1 = client.CoreV1API()
        self.current_token = None
        self.token_expiry = None

    def get_token(self, audience="openshift"):
        """Get or refresh bound token"""

        # Check if token is still valid (refresh at 80% of lifetime)
        if self.current_token and self.token_expiry:
            if time.time() < self.token_expiry * 0.8:
                return self.current_token

        # Create new token
        token_request = client.V1TokenRequest(
            spec=client.V1TokenRequestSpec(
                audiences=[audience],
                expiration_seconds=3600
            )
        )

        response = self.v1.create_namespaced_service_account_token(
            "default", "my-service-account", token_request
        )

        self.current_token = response.status.token
        self.token_expiry = response.status.expiration_timestamp

        return self.current_token

# Usage
token_manager = BoundTokenManager()
token = token_manager.get_token()
```

## Best Practices

### Security Best Practices

1. **Key Storage**: Store private keys only in Kubernetes secrets
2. **Access Control**: Limit access to signing key secrets using RBAC
3. **Regular Rotation**: Rotate keys only if compromise is suspected
4. **Monitoring**: Monitor token creation and validation metrics
5. **Backup Strategy**: Maintain secure backups of private keys

### Operational Best Practices

1. **Token Refresh**: Implement automatic token refresh in applications
2. **Error Handling**: Handle token expiration gracefully
3. **Caching**: Cache public keys for better performance
4. **Testing**: Regularly test token validation workflows
5. **Documentation**: Keep documentation up to date

### Performance Best Practices

1. **Batch Operations**: Create multiple tokens in a single request when possible
2. **Connection Reuse**: Reuse HTTP connections for OIDC discovery
3. **Local Caching**: Cache public keys locally in third-party systems
4. **Appropriate Expiration**: Use appropriate token expiration times
5. **Monitoring**: Monitor API server latency for token validation

## Conclusion

You now have bound token authentication configured in your HyperShift cluster. Key points to remember:

- **Bound tokens** are more secure than traditional service account tokens
- **Token refresh** is handled automatically by the token minter
- **Third-party validation** requires access to the cluster's public keys
- **Key rotation** is a manual process that should be planned carefully
- **Monitoring** is essential for detecting issues early

For more detailed information, see the [Bound Token Management Reference](../../reference/authentication/bound-token-management.md) guide.

## Troubleshooting

If you encounter issues:

1. **Check the logs** of the token minter pod
2. **Validate the configuration** using the provided scripts
3. **Verify RBAC permissions** for service accounts
4. **Test token creation** manually
5. **Check network connectivity** for OIDC discovery

For additional support, refer to the [HyperShift documentation](https://hypershift.docs.openshift.com/) or open an issue on the [GitHub repository](https://github.com/openshift/hypershift).
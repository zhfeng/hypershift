#!/bin/bash

# key-generation.sh - Generate RSA key pairs for bound token signing
#
# This script generates RSA key pairs suitable for HyperShift bound token signing.
# It creates both private and public keys in the required format.
#
# Usage: ./key-generation.sh <key-name> [key-size]
# Example: ./key-generation.sh my-signing-key 2048

set -e

# Configuration
KEY_NAME="${1:-my-signing-key}"
KEY_SIZE="${2:-2048}"
OUTPUT_DIR="generated-keys"
NAMESPACE="clusters"

# Validate key size
case $KEY_SIZE in
    2048|3072|4096)
        echo "Using key size: $KEY_SIZE bits"
        ;;
    *)
        echo "Error: Invalid key size. Use 2048, 3072, or 4096"
        exit 1
        ;;
esac

# Create output directory
mkdir -p "$OUTPUT_DIR"
cd "$OUTPUT_DIR"

echo "=== Generating RSA key pair for bound token signing ==="
echo "Key name: $KEY_NAME"
echo "Key size: $KEY_SIZE bits"
echo "Output directory: $(pwd)"
echo ""

# Generate private key
echo "1. Generating private key..."
openssl genrsa -out "${KEY_NAME}.pem" "$KEY_SIZE"
echo "✅ Private key generated: ${KEY_NAME}.pem"

# Generate public key
echo "2. Extracting public key..."
openssl rsa -in "${KEY_NAME}.pem" -pubout -out "${KEY_NAME}-pub.pem"
echo "✅ Public key generated: ${KEY_NAME}-pub.pem"

# Verify keys
echo "3. Verifying keys..."
if openssl rsa -in "${KEY_NAME}.pem" -check -noout >/dev/null 2>&1; then
    echo "✅ Private key is valid"
else
    echo "❌ Private key is invalid"
    exit 1
fi

if openssl rsa -pubin -in "${KEY_NAME}-pub.pem" -text -noout >/dev/null 2>&1; then
    echo "✅ Public key is valid"
else
    echo "❌ Public key is invalid"
    exit 1
fi

# Display key information
echo "4. Key information:"
echo "   Private key: $(openssl rsa -in "${KEY_NAME}.pem" -text -noout | grep 'Private-Key' | cut -d: -f2 | tr -d ' ')"
echo "   Public key exponent: $(openssl rsa -in "${KEY_NAME}.pem" -text -noout | grep 'publicExponent' | cut -d: -f2 | tr -d ' ')"

# Create Kubernetes secret manifest
echo "5. Creating Kubernetes secret manifest..."
cat > "${KEY_NAME}-secret.yaml" << EOF
apiVersion: v1
kind: Secret
metadata:
  name: ${KEY_NAME}
  namespace: ${NAMESPACE}
  labels:
    hypershift.openshift.io/signing-key: "true"
  annotations:
    hypershift.openshift.io/key-generated: "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    hypershift.openshift.io/key-size: "${KEY_SIZE}"
type: Opaque
data:
  service-account-signing-key: $(cat "${KEY_NAME}.pem" | base64 -w 0)
  service-account-signing-key-pub: $(cat "${KEY_NAME}-pub.pem" | base64 -w 0)
EOF
echo "✅ Secret manifest created: ${KEY_NAME}-secret.yaml"

# Create HostedCluster snippet
echo "6. Creating HostedCluster configuration snippet..."
cat > "${KEY_NAME}-hostedcluster-snippet.yaml" << EOF
# Add this to your HostedCluster spec:
apiVersion: hypershift.openshift.io/v1beta1
kind: HostedCluster
metadata:
  name: your-cluster-name
spec:
  oidcProviders:
  - issuerURL: https://oidc.example.com
    serviceAccountSigningKey:
      name: ${KEY_NAME}
  # ... other configuration
EOF
echo "✅ HostedCluster snippet created: ${KEY_NAME}-hostedcluster-snippet.yaml"

# Create example validation script
echo "7. Creating validation script..."
cat > "validate-${KEY_NAME}.sh" << 'EOF'
#!/bin/bash

# validation script for bound token keys
set -e

KEY_NAME="${1}"
NAMESPACE="${2:-clusters}"

if [ -z "$KEY_NAME" ]; then
    echo "Usage: $0 <key-name> [namespace]"
    exit 1
fi

echo "=== Validating bound token key: $KEY_NAME ==="

# Check if secret exists
echo "1. Checking secret existence..."
if kubectl get secret "$KEY_NAME" -n "$NAMESPACE" >/dev/null 2>&1; then
    echo "✅ Secret exists in namespace $NAMESPACE"
else
    echo "❌ Secret not found. Apply the secret manifest first."
    exit 1
fi

# Validate private key
echo "2. Validating private key..."
PRIVATE_KEY=$(kubectl get secret "$KEY_NAME" -n "$NAMESPACE" -o jsonpath='{.data.service-account-signing-key}')
if echo "$PRIVATE_KEY" | base64 -d | openssl rsa -check -noout >/dev/null 2>&1; then
    echo "✅ Private key is valid"
else
    echo "❌ Private key is invalid"
    exit 1
fi

# Validate public key
echo "3. Validating public key..."
PUBLIC_KEY=$(kubectl get secret "$KEY_NAME" -n "$NAMESPACE" -o jsonpath='{.data.service-account-signing-key-pub}')
if echo "$PUBLIC_KEY" | base64 -d | openssl rsa -pubin -text -noout >/dev/null 2>&1; then
    echo "✅ Public key is valid"
else
    echo "❌ Public key is invalid"
    exit 1
fi

# Check key pair compatibility
echo "4. Checking key pair compatibility..."
TEMP_DIR=$(mktemp -d)
echo "$PRIVATE_KEY" | base64 -d > "$TEMP_DIR/private.pem"
echo "$PUBLIC_KEY" | base64 -d > "$TEMP_DIR/public.pem"

# Extract public key from private key
openssl rsa -in "$TEMP_DIR/private.pem" -pubout -out "$TEMP_DIR/derived-public.pem"

if diff "$TEMP_DIR/public.pem" "$TEMP_DIR/derived-public.pem" >/dev/null 2>&1; then
    echo "✅ Public key matches private key"
else
    echo "❌ Public key does not match private key"
    rm -rf "$TEMP_DIR"
    exit 1
fi

rm -rf "$TEMP_DIR"

# Show key information
echo "5. Key information:"
PRIVATE_KEY_INFO=$(echo "$PRIVATE_KEY" | base64 -d | openssl rsa -text -noout | grep 'Private-Key' | cut -d: -f2 | tr -d ' ')
echo "   Key type: RSA $PRIVATE_KEY_INFO"
echo "   Secret name: $KEY_NAME"
echo "   Namespace: $NAMESPACE"

echo ""
echo "✅ All validations passed! The key pair is ready for use."
EOF

chmod +x "validate-${KEY_NAME}.sh"
echo "✅ Validation script created: validate-${KEY_NAME}.sh"

# Display next steps
echo ""
echo "=== Next Steps ==="
echo "1. Apply the secret to Kubernetes:"
echo "   kubectl apply -f ${KEY_NAME}-secret.yaml"
echo ""
echo "2. Validate the keys:"
echo "   ./validate-${KEY_NAME}.sh $KEY_NAME"
echo ""
echo "3. Update your HostedCluster configuration:"
echo "   Add the OIDC provider configuration from ${KEY_NAME}-hostedcluster-snippet.yaml"
echo ""
echo "4. Test token creation:"
echo "   kubectl create token default -n default --duration=1h"
echo ""
echo "Files created in $(pwd):"
echo "  - ${KEY_NAME}.pem (private key)"
echo "  - ${KEY_NAME}-pub.pem (public key)"
echo "  - ${KEY_NAME}-secret.yaml (Kubernetes secret manifest)"
echo "  - ${KEY_NAME}-hostedcluster-snippet.yaml (HostedCluster config)"
echo "  - validate-${KEY_NAME}.sh (validation script)"
echo ""
echo "🔐 Keep the private key secure and never commit it to version control!"
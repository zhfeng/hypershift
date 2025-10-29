# Bound Token Examples

This directory contains practical examples for working with bound service account tokens in HyperShift.

## Overview

These examples demonstrate:

- RSA key generation for bound token signing
- HostedCluster configuration with custom signing keys
- Third-party token validation in multiple languages
- Monitoring and troubleshooting scripts
- Migration from traditional service account tokens

## Security Notice

⚠️ **Important**: These examples are for demonstration purposes. In production environments:

- Use proper key management practices
- Secure your private keys
- Implement appropriate access controls
- Monitor token usage and validation

## Examples

### 1. Key Generation Scripts

- [`key-generation.sh`](./key-generation.sh) - Generate RSA key pairs for bound token signing
- [`key-rotation.sh`](./key-rotation.sh) - Automated key rotation procedure

### 2. Configuration Examples

- [`hostedcluster-aws.yaml`](./hostedcluster-aws.yaml) - AWS HostedCluster with bound tokens
- [`hostedcluster-azure.yaml`](./hostedcluster-azure.yaml) - Azure HostedCluster with bound tokens
- [`hostedcluster-generic.yaml`](./hostedcluster-generic.yaml) - Generic platform HostedCluster

### 3. Token Validation Examples

- [`validate-token-python.py`](./validate-token-python.py) - Python token validation
- [`validate-token-go.go`](./validate-token-go.go) - Go token validation
- [`validate-token-java.java`](./validate-token-java.java) - Java token validation
- [`validate-token-node.js`](./validate-token-node.js) - Node.js token validation

### 4. Application Examples

- [`token-client-python/`](./token-client-python/) - Python application using bound tokens
- [`token-client-go/`](./token-client-go/) - Go application using bound tokens

### 5. Monitoring Scripts

- [`monitor-tokens.sh`](./monitor-tokens.sh) - Monitor token creation and usage
- [`validate-setup.sh`](./validate-setup.sh) - Validate bound token configuration
- [`troubleshoot-tokens.sh`](./troubleshoot-tokens.sh) - Troubleshoot common issues

## Quick Start

1. **Generate keys**:
   ```bash
   ./key-generation.sh my-signing-key
   ```

2. **Configure HostedCluster**:
   ```bash
   kubectl apply -f hostedcluster-generic.yaml
   ```

3. **Test validation**:
   ```bash
   ./validate-setup.sh my-cluster
   ```

4. **Run examples**:
   ```bash
   python validate-token-python.py $TOKEN $CLUSTER_URL
   ```

## Requirements

- **kubectl** with access to service cluster
- **OpenSSL** for key generation
- **Python 3.7+** for Python examples
- **Go 1.19+** for Go examples
- **Node.js 16+** for Node.js examples
- **Java 11+** for Java examples

## Configuration

Before running the examples:

1. Update the cluster name and namespace in configuration files
2. Ensure you have appropriate RBAC permissions
3. Configure your platform-specific settings (AWS, Azure, etc.)
4. Update issuer URLs to match your environment

## Support

For issues with these examples:

1. Check the [HyperShift documentation](https://hypershift.docs.openshift.com/)
2. Review the main [bound token documentation](../../../docs/content/reference/authentication/bound-token-management.md)
3. Open an issue on the [HyperShift GitHub repository](https://github.com/openshift/hypershift)

## Contributing

To contribute new examples:

1. Follow the existing code style and structure
2. Add appropriate error handling
3. Include comprehensive comments
4. Update this README file
5. Test in multiple environments

## License

These examples are licensed under the same terms as the HyperShift project.
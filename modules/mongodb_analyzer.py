"""
MongoDB Analyzer Module
Analyzes API configurations, policies, and security settings from MongoDB
"""

from pymongo import MongoClient
from typing import Dict, List, Optional
from collections import defaultdict


class MongoDBAnalyzer:
    """Analyzes MongoDB data for API security configurations"""
    
    def __init__(self, mongodb_uri: str, db_name: str):
        """Initialize MongoDB connection"""
        self.client = MongoClient(mongodb_uri)
        self.db = self.client[db_name]
        
    def close(self):
        """Close MongoDB connection"""
        if self.client:
            self.client.close()
    
    def get_api_list(self) -> List[Dict]:
        """Get list of all APIs with basic info"""
        apis = []
        for api in self.db.api_proxy.find({}, {
            '_id': 1,
            'name': 1,
            'apiProxyDeployList': 1,
            'requestPolicyList': 1,
            'responsePolicyList': 1,
            'createdDate': 1,
            'updatedDate': 1
        }):
            # Get deployed environments
            deployed_envs = []
            for deploy in api.get('apiProxyDeployList', []):
                if deploy.get('deploy'):
                    deployed_envs.append({
                        'name': deploy.get('environmentName'),
                        'url': deploy.get('accessUrl'),
                        'protocol': deploy.get('environmentCommunicationProtocolType')
                    })

            apis.append({
                'id': str(api['_id']),
                'service_name': api.get('name', 'Unknown'),
                'deployed_environments': deployed_envs,
                'request_policies': len(api.get('requestPolicyList', [])),
                'response_policies': len(api.get('responsePolicyList', [])),
                'created_date': api.get('createdDate'),
                'updated_date': api.get('updatedDate')
            })

        return apis

    def get_security_statistics(self) -> Dict:
        """Get security statistics from MongoDB without ES queries - EXACTLY like policy_usage_statistics.py"""

        # Authentication Policies
        auth_policies = [
            'PolicyApiAuthentication', 'PolicyBasicAuthentication', 'PolicyDigestAuthentication',
            'PolicyJwtAuthentication', 'PolicyOauth2Authentication', 'PolicyMTLSAuthentication',
            'PolicyBase64Authentication'
        ]

        # Security Policies
        security_policies = [
            'PolicyIpWhite', 'PolicyIpBlack', 'PolicyAllowedHours', 'PolicyClientBanner',
            'PolicySaml', 'PolicyCondition'
        ]

        # Rate Limiting Policies
        throttling_policies = [
            'PolicyApiBasedThrottling', 'PolicyApiBasedQuota', 'PolicyEndpointRateLimit'
        ]

        total_apis = 0
        with_security = 0
        with_throttling = 0
        with_auth = 0

        for api in self.db.api_proxy.find({}, {
            'requestPolicyList._class': 1,
            'responsePolicyList._class': 1,
            'errorPolicyList._class': 1
        }):
            total_apis += 1

            has_security = False
            has_throttling = False
            has_auth = False

            # Check all policy lists
            all_policies = []
            all_policies.extend(api.get('requestPolicyList', []))
            all_policies.extend(api.get('responsePolicyList', []))
            all_policies.extend(api.get('errorPolicyList', []))

            for policy in all_policies:
                # Get policy class name (e.g., "com.apinizer.policy.PolicyIpWhite" -> "PolicyIpWhite")
                policy_class = policy.get('_class', '').split('.')[-1]

                # Check if it's a security policy
                if policy_class in security_policies:
                    has_security = True

                # Check if it's a throttling policy
                if policy_class in throttling_policies:
                    has_throttling = True

                # Check if it's an authentication policy
                if policy_class in auth_policies:
                    has_auth = True

            if has_security:
                with_security += 1
            if has_throttling:
                with_throttling += 1
            if has_auth:
                with_auth += 1

        return {
            'total_apis': total_apis,
            'with_security': with_security,
            'with_throttling': with_throttling,
            'with_auth': with_auth,
            'security_percentage': (with_security / total_apis * 100) if total_apis > 0 else 0,
            'throttling_percentage': (with_throttling / total_apis * 100) if total_apis > 0 else 0,
            'auth_percentage': (with_auth / total_apis * 100) if total_apis > 0 else 0
        }
    
    def get_api_details(self, api_id: str) -> Optional[Dict]:
        """Get detailed information about a specific API"""
        from bson.objectid import ObjectId
        
        try:
            api = self.db.api_proxy.find_one({'_id': ObjectId(api_id)})
            if not api:
                return None
            
            # Parse policies
            policies = self._parse_policies(api)
            
            # Get deployed environments
            deployed_envs = []
            for deploy in api.get('apiProxyDeployList', []):
                if deploy.get('deploy'):
                    deployed_envs.append({
                        'name': deploy.get('environmentName'),
                        'url': deploy.get('accessUrl'),
                        'protocol': deploy.get('environmentCommunicationProtocolType'),
                        'environment_id': str(deploy.get('environmentSettingsId'))
                    })
            
            # Check backend SSL
            backend_ssl = self._check_backend_ssl(api)

            # Check client SSL
            client_ssl = self._check_client_ssl(api)

            # Check if logs are enabled
            logs_enabled = self._check_logs_enabled(api)

            return {
                'id': str(api['_id']),
                'service_name': api.get('name', 'Unknown'),
                'deployed_environments': deployed_envs,
                'policies': policies,
                'created_date': api.get('createdDate'),
                'updated_date': api.get('updatedDate'),
                'description': api.get('description', ''),
                'version': api.get('version', '1.0'),
                'backend_ssl': backend_ssl,
                'client_ssl': client_ssl,
                'logs_enabled': logs_enabled
            }
        except Exception as e:
            print(f"Error getting API details: {e}")
            return None

    def _check_backend_ssl(self, api: Dict) -> Dict:
        """Check if backend uses SSL/TLS"""
        routing = api.get('routing', {})
        routing_addresses = routing.get('routingAddressWrapperList', [])

        total_backends = len(routing_addresses)
        ssl_backends = 0
        non_ssl_backends = []

        for addr in routing_addresses:
            address = addr.get('address', '')
            if address.startswith('https://'):
                ssl_backends += 1
            elif address.startswith('http://'):
                non_ssl_backends.append(address)

        return {
            'total': total_backends,
            'ssl_count': ssl_backends,
            'non_ssl_count': total_backends - ssl_backends,
            'non_ssl_addresses': non_ssl_backends,
            'all_ssl': ssl_backends == total_backends and total_backends > 0
        }

    def _check_client_ssl(self, api: Dict) -> Dict:
        """Check if deployed environments use SSL/TLS"""
        deploy_list = api.get('apiProxyDeployList', [])

        total_deployed = 0
        ssl_deployed = 0
        non_ssl_deployed = []

        for deploy in deploy_list:
            if deploy.get('deploy'):
                total_deployed += 1
                access_url = deploy.get('accessUrl', '')
                env_name = deploy.get('environmentName', 'Unknown')

                if access_url.startswith('https://'):
                    ssl_deployed += 1
                elif access_url.startswith('http://'):
                    non_ssl_deployed.append({
                        'environment': env_name,
                        'url': access_url
                    })

        return {
            'total': total_deployed,
            'ssl_count': ssl_deployed,
            'non_ssl_count': total_deployed - ssl_deployed,
            'non_ssl_environments': non_ssl_deployed,
            'all_ssl': ssl_deployed == total_deployed and total_deployed > 0
        }

    def _check_logs_enabled(self, api: Dict) -> Dict:
        """Check if logging is enabled"""
        app_log_settings = api.get('applicationLogSettings', {})
        trace_settings = api.get('traceSettings', {})

        # Check if trace log is enabled
        trace_enabled = app_log_settings.get('enableTraceLog', False) or trace_settings.get('enableTraceLog', False)

        return {
            'trace_enabled': trace_enabled,
            'application_log_settings': app_log_settings,
            'trace_settings': trace_settings
        }

    def _parse_policies(self, api: Dict) -> Dict:
        """Parse and categorize policies - EXACTLY like policy_usage_statistics.py"""
        policies = {
            'request': [],
            'response': [],
            'error': []
        }

        # Request policies
        for policy in api.get('requestPolicyList', []):
            # Get policy class name (e.g., "com.apinizer.policy.PolicyIpWhite" -> "PolicyIpWhite")
            policy_class = policy.get('_class', '').split('.')[-1]

            policy_info = {
                'type': policy_class,
                'enabled': policy.get('enabled', True),  # Default True if not specified
                'order': policy.get('order', 0),
                'direction': 'request',
                'full_class': policy.get('_class', '')
            }
            policies['request'].append(policy_info)

        # Response policies
        for policy in api.get('responsePolicyList', []):
            policy_class = policy.get('_class', '').split('.')[-1]

            policy_info = {
                'type': policy_class,
                'enabled': policy.get('enabled', True),
                'order': policy.get('order', 0),
                'direction': 'response',
                'full_class': policy.get('_class', '')
            }
            policies['response'].append(policy_info)

        # Error policies
        for policy in api.get('errorPolicyList', []):
            policy_class = policy.get('_class', '').split('.')[-1]

            policy_info = {
                'type': policy_class,
                'enabled': policy.get('enabled', True),
                'order': policy.get('order', 0),
                'direction': 'error',
                'full_class': policy.get('_class', '')
            }
            policies['error'].append(policy_info)

        return policies
    
    def get_policy_statistics(self) -> Dict:
        """Get overall policy usage statistics - EXACTLY like policy_usage_statistics.py"""

        # Authentication Policies
        auth_policies = [
            'PolicyApiAuthentication', 'PolicyBasicAuthentication', 'PolicyDigestAuthentication',
            'PolicyJwtAuthentication', 'PolicyOauth2Authentication', 'PolicyMTLSAuthentication',
            'PolicyBase64Authentication'
        ]

        # Security Policies
        security_policies = [
            'PolicyIpWhite', 'PolicyIpBlack', 'PolicyAllowedHours', 'PolicyClientBanner',
            'PolicySaml', 'PolicyCondition'
        ]

        # Rate Limiting Policies
        throttling_policies = [
            'PolicyApiBasedThrottling', 'PolicyApiBasedQuota', 'PolicyEndpointRateLimit'
        ]

        total_apis = 0
        with_security = 0
        with_throttling = 0
        with_auth = 0

        for api in self.db.api_proxy.find({}, {
            'requestPolicyList._class': 1,
            'responsePolicyList._class': 1,
            'errorPolicyList._class': 1
        }):
            total_apis += 1

            has_security = False
            has_throttling = False
            has_auth = False

            # Check all policy lists
            all_policies = []
            all_policies.extend(api.get('requestPolicyList', []))
            all_policies.extend(api.get('responsePolicyList', []))
            all_policies.extend(api.get('errorPolicyList', []))

            for policy in all_policies:
                # Get policy class name (e.g., "com.apinizer.policy.PolicyIpWhite" -> "PolicyIpWhite")
                policy_class = policy.get('_class', '').split('.')[-1]

                # Check if it's a security policy
                if policy_class in security_policies:
                    has_security = True

                # Check if it's a throttling policy
                if policy_class in throttling_policies:
                    has_throttling = True

                # Check if it's an authentication policy
                if policy_class in auth_policies:
                    has_auth = True

            if has_security:
                with_security += 1
            if has_throttling:
                with_throttling += 1
            if has_auth:
                with_auth += 1

        return {
            'total_apis': total_apis,
            'with_security': with_security,
            'with_throttling': with_throttling,
            'with_auth': with_auth,
            'security_percentage': (with_security / total_apis * 100) if total_apis > 0 else 0,
            'throttling_percentage': (with_throttling / total_apis * 100) if total_apis > 0 else 0,
            'auth_percentage': (with_auth / total_apis * 100) if total_apis > 0 else 0
        }
    
    def get_ip_groups(self) -> List[Dict]:
        """Get all IP groups"""
        ip_groups = []
        for group in self.db.ip_group.find({}):
            ip_groups.append({
                'id': str(group['_id']),
                'name': group.get('name', 'Unknown'),
                'ips': group.get('ipList', []),
                'description': group.get('description', '')
            })
        return ip_groups
    
    def get_api_deployment_map(self) -> Dict[str, Dict]:
        """Get API deployment information mapping"""
        deployment_map = {}

        for api in self.db.api_proxy.find({}, {
            '_id': 1,
            'serviceName': 1,
            'apiProxyDeployList': 1
        }):
            api_id = str(api['_id'])
            service_name = api.get('serviceName', 'Unknown')

            deployed_envs = []
            for deploy in api.get('apiProxyDeployList', []):
                if deploy.get('deploy'):
                    deployed_envs.append(deploy.get('environmentName'))

            deployment_map[api_id] = {
                'service_name': service_name,
                'environments': deployed_envs
            }

        return deployment_map

    def get_elasticsearch_configs(self) -> List[Dict]:
        """
        Get Elasticsearch configurations from MongoDB connection_config_elasticsearch collection
        Returns list of ES configs in the format expected by the application
        """
        es_configs = []

        try:
            # Query enabled READ_WRITE Elasticsearch connections
            for es_conn in self.db.connection_config_elasticsearch.find({
                'enabled': True,
                'type': 'READ_WRITE'
            }):
                # Build URL from elasticHostList
                elastic_hosts = es_conn.get('elasticHostList', [])
                if not elastic_hosts:
                    continue

                # Use first host (can be extended to support multiple hosts)
                first_host = elastic_hosts[0]
                scheme = first_host.get('scheme', 'HTTP').lower()
                host = first_host.get('host', 'localhost')
                port = first_host.get('port', 9200)
                url = f"{scheme}://{host}:{port}"

                # Get authentication info
                username = es_conn.get('username', '')
                password = es_conn.get('password', '')

                # Get index name/pattern
                index_pattern = es_conn.get('indexName', 'apinizer-log-apiproxy-default')

                # Get connection name
                name = es_conn.get('name', 'Unknown-ES')

                es_config = {
                    'name': name,
                    'url': url,
                    'username': username,
                    'password': password,
                    'index_pattern': index_pattern,
                    'authenticate': es_conn.get('authenticate', False),
                    'project_id': es_conn.get('projectId', 'admin')
                }

                es_configs.append(es_config)

        except Exception as e:
            print(f"Error getting Elasticsearch configs from MongoDB: {e}")
            # Return empty list if there's an error
            return []

        return es_configs


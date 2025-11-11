"""
Security Scorer Module
Calculates security scores for APIs based on multiple factors
"""

from typing import Dict, List
from datetime import datetime


class SecurityScorer:
    """Calculates comprehensive security scores for APIs"""
    
    def __init__(self, weights: Dict[str, float]):
        """
        Initialize scorer with weights
        
        Args:
            weights: Dictionary of score component weights
        """
        self.weights = weights
    
    def calculate_api_score(self, api_config: Dict, traffic_stats: Dict) -> Dict:
        """
        Calculate comprehensive security score for an API
        
        Args:
            api_config: API configuration from MongoDB
            traffic_stats: Traffic statistics from Elasticsearch
            
        Returns:
            Dictionary with score breakdown and recommendations
        """
        scores = {}
        recommendations = []
        
        # 1. IP Whitelist Coverage Score (0-100)
        ip_score, ip_recs = self._score_ip_whitelist(api_config, traffic_stats)
        scores['ip_whitelist_coverage'] = ip_score
        recommendations.extend(ip_recs)
        
        # 2. Throttling Configuration Score (0-100)
        throttle_score, throttle_recs = self._score_throttling(api_config, traffic_stats)
        scores['throttling_configured'] = throttle_score
        recommendations.extend(throttle_recs)
        
        # 3. Quota Configuration Score (0-100)
        quota_score, quota_recs = self._score_quota(api_config, traffic_stats)
        scores['quota_configured'] = quota_score
        recommendations.extend(quota_recs)
        
        # 4. Authentication Strength Score (0-100)
        auth_score, auth_recs = self._score_authentication(api_config)
        scores['authentication_strength'] = auth_score
        recommendations.extend(auth_recs)

        # 5. Allowed Hours Score (0-100)
        allowed_hours_score, allowed_hours_recs = self._score_allowed_hours(api_config, traffic_stats)
        scores['allowed_hours'] = allowed_hours_score
        recommendations.extend(allowed_hours_recs)

        # 6. Traffic Anomaly Score (0-100, higher is better = less anomaly)
        anomaly_score, anomaly_recs = self._score_traffic_anomaly(traffic_stats)
        scores['traffic_anomaly'] = anomaly_score
        recommendations.extend(anomaly_recs)

        # 7. Error Rate Score (0-100, higher is better = less errors)
        error_score, error_recs = self._score_error_rate(traffic_stats)
        scores['error_rate'] = error_score
        recommendations.extend(error_recs)

        # 8. SSL/TLS Status Score (0-100)
        ssl_score, ssl_recs = self._score_ssl_tls(api_config)
        scores['ssl_tls_status'] = ssl_score
        recommendations.extend(ssl_recs)

        # 9. Logging Status Score (0-100)
        logging_score, logging_recs = self._score_logging(api_config, traffic_stats)
        scores['logging_status'] = logging_score
        recommendations.extend(logging_recs)

        # Calculate weighted total score
        total_score = 0
        for component, score in scores.items():
            weight = self.weights.get(component, 0)
            total_score += score * weight
        
        # Determine security level
        security_level = self._get_security_level(total_score)
        
        return {
            'total_score': round(total_score, 2),
            'security_level': security_level,
            'component_scores': scores,
            'recommendations': recommendations,
            'calculated_at': datetime.now().isoformat()
        }
    
    def _score_ip_whitelist(self, api_config: Dict, traffic_stats: Dict) -> tuple:
        """Score IP whitelist configuration"""
        score = 0
        recommendations = []

        policies = api_config.get('policies', {})

        # Check all policy lists (request, response, error)
        all_policies = []
        all_policies.extend(policies.get('request', []))
        all_policies.extend(policies.get('response', []))
        all_policies.extend(policies.get('error', []))

        # Check if IP whitelist policy exists AND is enabled
        has_ip_whitelist = any(
            p['type'] == 'PolicyIpWhite' and p.get('enabled', True)
            for p in all_policies
        )

        if has_ip_whitelist:
            score = 100
        else:
            score = 0
            unique_ips = traffic_stats.get('unique_ips', 0)
            if unique_ips > 0 and unique_ips <= 10:
                recommendations.append({
                    'severity': 'medium',
                    'category': 'ip_whitelist',
                    'message': f'API has {unique_ips} unique IPs but no IP whitelist configured. Consider adding IP whitelist policy.',
                    'action': 'Add PolicyIpWhite to restrict access to known IPs'
                })

        return score, recommendations
    
    def _score_throttling(self, api_config: Dict, traffic_stats: Dict) -> tuple:
        """Score throttling configuration"""
        score = 0
        recommendations = []

        policies = api_config.get('policies', {})

        # Check all policy lists
        all_policies = []
        all_policies.extend(policies.get('request', []))
        all_policies.extend(policies.get('response', []))
        all_policies.extend(policies.get('error', []))

        # Check if throttling policy exists AND is enabled
        has_throttling = any(
            p['type'] in ['PolicyApiBasedThrottling', 'PolicyEndpointRateLimit'] and p.get('enabled', True)
            for p in all_policies
        )

        if has_throttling:
            score = 100
        else:
            score = 0
            max_per_hour = traffic_stats.get('max_requests_per_hour', 0)
            if max_per_hour > 1000:
                recommendations.append({
                    'severity': 'high',
                    'category': 'throttling',
                    'message': f'High traffic API ({max_per_hour} req/hour) without throttling. Risk of abuse.',
                    'action': f'Add throttling policy with limit ~{int(max_per_hour * 1.2)} req/hour'
                })
            elif max_per_hour > 0:
                recommendations.append({
                    'severity': 'low',
                    'category': 'throttling',
                    'message': 'No throttling policy configured.',
                    'action': f'Consider adding throttling policy with limit ~{int(max_per_hour * 1.2)} req/hour'
                })

        return score, recommendations
    
    def _score_quota(self, api_config: Dict, traffic_stats: Dict) -> tuple:
        """Score quota configuration"""
        score = 0
        recommendations = []

        policies = api_config.get('policies', {})

        # Check all policy lists
        all_policies = []
        all_policies.extend(policies.get('request', []))
        all_policies.extend(policies.get('response', []))
        all_policies.extend(policies.get('error', []))

        # Check if quota policy exists AND is enabled
        has_quota = any(
            p['type'] == 'PolicyApiBasedQuota' and p.get('enabled', True)
            for p in all_policies
        )

        if has_quota:
            score = 100
        else:
            score = 50  # Not critical, but recommended
            total_requests = traffic_stats.get('total_requests', 0)
            if total_requests > 10000:
                recommendations.append({
                    'severity': 'medium',
                    'category': 'quota',
                    'message': 'High-volume API without quota limits.',
                    'action': 'Consider adding quota policy for cost control and fair usage'
                })

        return score, recommendations
    
    def _score_authentication(self, api_config: Dict) -> tuple:
        """Score authentication configuration"""
        score = 0
        recommendations = []

        policies = api_config.get('policies', {})

        # Check all policy lists
        all_policies = []
        all_policies.extend(policies.get('request', []))
        all_policies.extend(policies.get('response', []))
        all_policies.extend(policies.get('error', []))

        # Check authentication policies (enabled only)
        auth_policy_types = [
            'PolicyApiAuthentication', 'PolicyBasicAuthentication',
            'PolicyJwtAuthentication', 'PolicyOauth2Authentication',
            'PolicyMTLSAuthentication', 'PolicyDigestAuthentication'
        ]

        auth_policies = [
            p for p in all_policies
            if p['type'] in auth_policy_types and p.get('enabled', True)
        ]

        if not auth_policies:
            score = 0
            recommendations.append({
                'severity': 'critical',
                'category': 'authentication',
                'message': 'No authentication policy configured. API is publicly accessible.',
                'action': 'Add authentication policy (OAuth2, JWT, or API Key recommended)'
            })
        else:
            # Score based on auth strength
            auth_types = [p['type'] for p in auth_policies]
            if 'PolicyOauth2Authentication' in auth_types or 'PolicyJwtAuthentication' in auth_types:
                score = 100  # Strong authentication
            elif 'PolicyMTLSAuthentication' in auth_types:
                score = 100  # Very strong authentication
            elif 'PolicyApiAuthentication' in auth_types:
                score = 75   # Medium authentication
            elif 'PolicyBasicAuthentication' in auth_types:
                score = 50   # Weak authentication
                recommendations.append({
                    'severity': 'medium',
                    'category': 'authentication',
                    'message': 'Using Basic Auth. Consider upgrading to OAuth2 or JWT.',
                    'action': 'Upgrade to stronger authentication method'
                })

        return score, recommendations

    def _score_allowed_hours(self, api_config: Dict, traffic_stats: Dict) -> tuple:
        """Score allowed hours configuration based on traffic patterns"""
        score = 100  # Default: no restriction needed
        recommendations = []

        policies = api_config.get('policies', {})

        # Check all policy lists
        all_policies = []
        all_policies.extend(policies.get('request', []))
        all_policies.extend(policies.get('response', []))
        all_policies.extend(policies.get('error', []))

        # Check if PolicyAllowedHours exists AND is enabled
        has_allowed_hours = any(
            p['type'] == 'PolicyAllowedHours' and p.get('enabled', True)
            for p in all_policies
        )

        if has_allowed_hours:
            # Already configured, perfect score
            score = 100
        else:
            # Analyze traffic patterns to see if restriction makes sense
            total_requests = traffic_stats.get('total_requests', 0)
            peak_hours = traffic_stats.get('peak_hours', [])

            # Only recommend if we have enough data
            if total_requests > 100 and peak_hours:
                # Calculate traffic concentration in peak hours
                # If traffic is highly concentrated in specific hours, recommend PolicyAllowedHours

                # Check if traffic is concentrated in business hours (8-18)
                business_hours = set(range(8, 19))  # 8 AM to 6 PM
                peak_hours_set = set(peak_hours)

                # If all peak hours are within business hours
                if peak_hours_set and peak_hours_set.issubset(business_hours):
                    score = 70  # Good, but could be better with restriction

                    # Format peak hours for display
                    peak_hours_str = ', '.join([f"{h:02d}:00" for h in sorted(peak_hours)])

                    recommendations.append({
                        'severity': 'low',
                        'category': 'allowed_hours',
                        'message': f'API traffic is concentrated in business hours (peak: {peak_hours_str}). Consider restricting access to business hours only.',
                        'action': f'Add PolicyAllowedHours to restrict access to {min(peak_hours):02d}:00-{max(peak_hours)+1:02d}:00'
                    })

                # If traffic is concentrated in specific hours (not spread across 24h)
                elif len(peak_hours) <= 8:  # Traffic concentrated in 8 hours or less
                    score = 75

                    peak_hours_str = ', '.join([f"{h:02d}:00" for h in sorted(peak_hours)])
                    start_hour = min(peak_hours)
                    end_hour = max(peak_hours) + 1

                    recommendations.append({
                        'severity': 'low',
                        'category': 'allowed_hours',
                        'message': f'API traffic is concentrated in specific hours (peak: {peak_hours_str}). Consider time-based access restriction.',
                        'action': f'Add PolicyAllowedHours to restrict access to {start_hour:02d}:00-{end_hour:02d}:00'
                    })

        return score, recommendations

    def _score_traffic_anomaly(self, traffic_stats: Dict) -> tuple:
        """Score based on traffic anomalies"""
        score = 100  # Start with perfect score
        recommendations = []
        
        avg_per_hour = traffic_stats.get('avg_requests_per_hour', 0)
        max_per_hour = traffic_stats.get('max_requests_per_hour', 0)
        
        if avg_per_hour > 0:
            # Check for traffic spikes
            spike_ratio = max_per_hour / avg_per_hour
            
            if spike_ratio > 10:
                score = 50
                recommendations.append({
                    'severity': 'high',
                    'category': 'anomaly',
                    'message': f'Severe traffic spike detected ({spike_ratio:.1f}x average). Possible attack or misconfiguration.',
                    'action': 'Investigate traffic patterns and consider adding rate limiting'
                })
            elif spike_ratio > 5:
                score = 70
                recommendations.append({
                    'severity': 'medium',
                    'category': 'anomaly',
                    'message': f'Significant traffic spike detected ({spike_ratio:.1f}x average).',
                    'action': 'Monitor traffic patterns and ensure adequate throttling'
                })
        
        return score, recommendations
    
    def _score_error_rate(self, traffic_stats: Dict) -> tuple:
        """Score based on error rate"""
        score = 100
        recommendations = []
        
        error_rate = traffic_stats.get('error_rate', 0)
        
        if error_rate > 20:
            score = 30
            recommendations.append({
                'severity': 'critical',
                'category': 'errors',
                'message': f'Very high error rate ({error_rate:.1f}%). Service may be failing.',
                'action': 'Investigate backend service health and error causes'
            })
        elif error_rate > 10:
            score = 60
            recommendations.append({
                'severity': 'high',
                'category': 'errors',
                'message': f'High error rate ({error_rate:.1f}%).',
                'action': 'Review error logs and improve error handling'
            })
        elif error_rate > 5:
            score = 80
            recommendations.append({
                'severity': 'medium',
                'category': 'errors',
                'message': f'Elevated error rate ({error_rate:.1f}%).',
                'action': 'Monitor error trends and investigate common failures'
            })
        
        return score, recommendations

    def _score_ssl_tls(self, api_config: Dict) -> tuple:
        """Score SSL/TLS configuration for both client and backend"""
        score = 0
        recommendations = []

        # Get SSL/TLS info
        client_ssl = api_config.get('client_ssl', {})
        backend_ssl = api_config.get('backend_ssl', {})

        # Client SSL (frontend - how clients connect to API)
        client_total = client_ssl.get('total', 0)
        client_ssl_count = client_ssl.get('ssl_count', 0)
        client_all_ssl = client_ssl.get('all_ssl', False)

        # Backend SSL (how API connects to backend services)
        backend_total = backend_ssl.get('total', 0)
        backend_ssl_count = backend_ssl.get('ssl_count', 0)
        backend_all_ssl = backend_ssl.get('all_ssl', False)

        # Calculate score (50% client, 50% backend)
        client_score = 0
        backend_score = 0

        # Client SSL Score
        if client_total > 0:
            if client_all_ssl:
                client_score = 100
            else:
                client_score = (client_ssl_count / client_total) * 100
                non_ssl_envs = client_ssl.get('non_ssl_environments', [])
                if non_ssl_envs:
                    env_names = ', '.join([env['environment'] for env in non_ssl_envs[:3]])
                    recommendations.append({
                        'severity': 'high',
                        'category': 'ssl_tls',
                        'message': f'Client connections without SSL/TLS detected in: {env_names}',
                        'action': 'Enable HTTPS for all client-facing endpoints to encrypt data in transit'
                    })
        else:
            client_score = 100  # No deployments, no issue

        # Backend SSL Score
        if backend_total > 0:
            if backend_all_ssl:
                backend_score = 100
            else:
                backend_score = (backend_ssl_count / backend_total) * 100
                non_ssl_backends = backend_ssl.get('non_ssl_addresses', [])
                if non_ssl_backends:
                    backend_list = ', '.join(non_ssl_backends[:3])
                    recommendations.append({
                        'severity': 'medium',
                        'category': 'ssl_tls',
                        'message': f'Backend connections without SSL/TLS: {backend_list}',
                        'action': 'Use HTTPS for backend service connections to ensure end-to-end encryption'
                    })
        else:
            backend_score = 100  # No backends, no issue

        # Combined score (client is more important - 60/40 split)
        score = (client_score * 0.6) + (backend_score * 0.4)

        return round(score, 2), recommendations

    def _score_logging(self, api_config: Dict, traffic_stats: Dict) -> tuple:
        """
        Score based on sensitive data exposure in logs

        Scoring Logic (based ONLY on sensitive data, not trace logging):
        - No sensitive data: 100 points (perfect)
        - Sensitive data found: penalty based on severity
          * >80% sensitive: 10 points (critical)
          * >50% sensitive: 20 points (critical)
          * >20% sensitive: 40 points (high risk)
          * >10% sensitive: 50 points (high risk)
          * >5% sensitive: 60 points (medium risk)
          * >1% sensitive: 70 points (low risk)
          * ≤1% sensitive: 80 points (minimal risk)
        """
        score = 100  # Default: no sensitive data
        recommendations = []

        # Get sensitive data info from traffic stats
        sensitive_data = traffic_stats.get('sensitive_data', {})
        has_sensitive_data = sensitive_data.get('has_sensitive_data', False)
        sensitive_keywords = sensitive_data.get('sensitive_keywords', {})

        # Check for sensitive data in logs
        if has_sensitive_data:
            # Sensitive data found in logs - major security issue
            total_logs = sensitive_data.get('total_logs_checked', 0)
            keyword_list = []

            for keyword, info in sensitive_keywords.items():
                percentage = info.get('percentage', 0)
                if percentage > 0:
                    keyword_list.append(f"{keyword} ({percentage:.1f}%)")

            if keyword_list:
                keywords_str = ', '.join(keyword_list[:5])  # Show first 5

                # Calculate severity based on MAX percentage across all keywords
                max_percentage = max([info.get('percentage', 0) for info in sensitive_keywords.values()])

                # More granular scoring based on percentage
                if max_percentage > 80:
                    score = 10  # Critical - almost all logs contain sensitive data
                    severity = 'critical'
                elif max_percentage > 50:
                    score = 20  # Critical - more than half of logs contain sensitive data
                    severity = 'critical'
                elif max_percentage > 20:
                    score = 40  # High risk
                    severity = 'high'
                elif max_percentage > 10:
                    score = 50  # High risk
                    severity = 'high'
                elif max_percentage > 5:
                    score = 60  # Medium risk
                    severity = 'medium'
                elif max_percentage > 1:
                    score = 70  # Low risk
                    severity = 'low'
                else:
                    score = 80  # Minimal risk - very few logs affected
                    severity = 'low'

                recommendations.append({
                    'severity': severity,
                    'category': 'logging',
                    'message': f'Sensitive data detected in logs: {keywords_str}. Checked {total_logs} logs.',
                    'action': 'Configure log masking/filtering to prevent sensitive data (TC, phone, password, etc.) from being logged'
                })

        return score, recommendations

    def _get_security_level(self, score: float) -> str:
        """Determine security level from score"""
        if score >= 90:
            return 'Excellent'
        elif score >= 75:
            return 'Good'
        elif score >= 60:
            return 'Fair'
        elif score >= 40:
            return 'Poor'
        else:
            return 'Critical'


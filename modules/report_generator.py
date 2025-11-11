"""
Report Generator Module
Generates comprehensive security reports in various formats
"""

from datetime import datetime
from typing import Dict, List
import json


class ReportGenerator:
    """Generates security reports"""
    
    def __init__(self):
        """Initialize report generator"""
        pass
    
    def generate_executive_summary(self, overview_data: Dict, 
                                   api_scores: List[Dict]) -> Dict:
        """
        Generate executive summary report
        
        Args:
            overview_data: Overview statistics
            api_scores: List of API security scores
            
        Returns:
            Executive summary dictionary
        """
        total_apis = overview_data.get('total_apis', 0)
        
        # Calculate average security score
        if api_scores:
            avg_score = sum(s['score']['total_score'] for s in api_scores) / len(api_scores)
        else:
            avg_score = 0
        
        # Count APIs by security level
        level_counts = {
            'Excellent': 0,
            'Good': 0,
            'Fair': 0,
            'Poor': 0,
            'Critical': 0
        }
        
        for api_score in api_scores:
            level = api_score['score']['security_level']
            level_counts[level] = level_counts.get(level, 0) + 1
        
        # Collect all recommendations
        all_recommendations = []
        for api_score in api_scores:
            for rec in api_score['score']['recommendations']:
                all_recommendations.append({
                    'api_name': api_score['api_name'],
                    **rec
                })
        
        # Group recommendations by severity
        critical_recs = [r for r in all_recommendations if r['severity'] == 'critical']
        high_recs = [r for r in all_recommendations if r['severity'] == 'high']
        medium_recs = [r for r in all_recommendations if r['severity'] == 'medium']
        low_recs = [r for r in all_recommendations if r['severity'] == 'low']
        
        return {
            'generated_at': datetime.now().isoformat(),
            'summary': {
                'total_apis': total_apis,
                'average_security_score': round(avg_score, 2),
                'apis_by_level': level_counts,
                'total_recommendations': len(all_recommendations),
                'critical_issues': len(critical_recs),
                'high_priority_issues': len(high_recs)
            },
            'top_issues': {
                'critical': critical_recs[:10],
                'high': high_recs[:10],
                'medium': medium_recs[:10]
            },
            'security_coverage': overview_data.get('security_coverage', {}),
            'recommendations_summary': self._summarize_recommendations(all_recommendations)
        }
    
    def _summarize_recommendations(self, recommendations: List[Dict]) -> Dict:
        """Summarize recommendations by category"""
        summary = {}
        
        for rec in recommendations:
            category = rec.get('category', 'other')
            if category not in summary:
                summary[category] = {
                    'count': 0,
                    'critical': 0,
                    'high': 0,
                    'medium': 0,
                    'low': 0
                }
            
            summary[category]['count'] += 1
            severity = rec.get('severity', 'low')
            summary[category][severity] += 1
        
        return summary
    
    def generate_api_detail_report(self, api_config: Dict, 
                                   traffic_stats: Dict,
                                   score_result: Dict) -> Dict:
        """
        Generate detailed report for a specific API
        
        Args:
            api_config: API configuration
            traffic_stats: Traffic statistics
            score_result: Security score result
            
        Returns:
            Detailed API report
        """
        return {
            'generated_at': datetime.now().isoformat(),
            'api_info': {
                'id': api_config['id'],
                'name': api_config['service_name'],
                'deployed_environments': api_config['deployed_environments'],
                'created_date': api_config.get('created_date'),
                'updated_date': api_config.get('updated_date')
            },
            'security_score': score_result,
            'traffic_analysis': {
                'total_requests': traffic_stats.get('total_requests', 0),
                'avg_requests_per_hour': traffic_stats.get('avg_requests_per_hour', 0),
                'max_requests_per_hour': traffic_stats.get('max_requests_per_hour', 0),
                'peak_hours': traffic_stats.get('peak_hours', []),
                'unique_ips': traffic_stats.get('unique_ips', 0),
                'unique_users': traffic_stats.get('unique_users', 0),
                'error_rate': traffic_stats.get('error_rate', 0),
                'success_rate': traffic_stats.get('success_rate', 0),
                'avg_response_time_ms': traffic_stats.get('avg_response_time_ms', 0)
            },
            'policy_configuration': api_config.get('policies', {}),
            'top_consumers': {
                'by_ip': traffic_stats.get('top_ips', []),
                'by_user': traffic_stats.get('top_users', [])
            },
            'recommendations': score_result.get('recommendations', [])
        }
    
    def generate_compliance_report(self, api_scores: List[Dict]) -> Dict:
        """
        Generate compliance report
        
        Args:
            api_scores: List of API security scores
            
        Returns:
            Compliance report
        """
        total_apis = len(api_scores)
        
        # Check compliance criteria
        compliance_checks = {
            'authentication_required': {
                'name': 'Authentication Required',
                'passed': 0,
                'failed': 0,
                'apis_failed': []
            },
            'ip_whitelist_configured': {
                'name': 'IP Whitelist Configured',
                'passed': 0,
                'failed': 0,
                'apis_failed': []
            },
            'throttling_enabled': {
                'name': 'Throttling Enabled',
                'passed': 0,
                'failed': 0,
                'apis_failed': []
            },
            'low_error_rate': {
                'name': 'Error Rate < 5%',
                'passed': 0,
                'failed': 0,
                'apis_failed': []
            },
            'security_score_acceptable': {
                'name': 'Security Score >= 60',
                'passed': 0,
                'failed': 0,
                'apis_failed': []
            }
        }
        
        for api_score in api_scores:
            api_name = api_score['api_name']
            score = api_score['score']
            traffic = api_score.get('traffic_stats', {})
            
            # Check authentication
            auth_score = score['component_scores'].get('authentication_strength', 0)
            if auth_score >= 50:
                compliance_checks['authentication_required']['passed'] += 1
            else:
                compliance_checks['authentication_required']['failed'] += 1
                compliance_checks['authentication_required']['apis_failed'].append(api_name)
            
            # Check IP whitelist
            ip_score = score['component_scores'].get('ip_whitelist_coverage', 0)
            if ip_score >= 50:
                compliance_checks['ip_whitelist_configured']['passed'] += 1
            else:
                compliance_checks['ip_whitelist_configured']['failed'] += 1
                compliance_checks['ip_whitelist_configured']['apis_failed'].append(api_name)
            
            # Check throttling
            throttle_score = score['component_scores'].get('throttling_configured', 0)
            if throttle_score >= 50:
                compliance_checks['throttling_enabled']['passed'] += 1
            else:
                compliance_checks['throttling_enabled']['failed'] += 1
                compliance_checks['throttling_enabled']['apis_failed'].append(api_name)
            
            # Check error rate
            error_rate = traffic.get('error_rate', 0)
            if error_rate < 5:
                compliance_checks['low_error_rate']['passed'] += 1
            else:
                compliance_checks['low_error_rate']['failed'] += 1
                compliance_checks['low_error_rate']['apis_failed'].append(api_name)
            
            # Check overall security score
            total_score = score['total_score']
            if total_score >= 60:
                compliance_checks['security_score_acceptable']['passed'] += 1
            else:
                compliance_checks['security_score_acceptable']['failed'] += 1
                compliance_checks['security_score_acceptable']['apis_failed'].append(api_name)
        
        # Calculate overall compliance percentage
        total_checks = len(compliance_checks) * total_apis
        total_passed = sum(c['passed'] for c in compliance_checks.values())
        compliance_percentage = (total_passed / total_checks * 100) if total_checks > 0 else 0
        
        return {
            'generated_at': datetime.now().isoformat(),
            'total_apis': total_apis,
            'compliance_percentage': round(compliance_percentage, 2),
            'checks': compliance_checks,
            'summary': {
                'total_checks': total_checks,
                'passed': total_passed,
                'failed': total_checks - total_passed
            }
        }
    
    def export_to_json(self, report: Dict, filename: str):
        """Export report to JSON file"""
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
    
    def export_to_html(self, report: Dict, filename: str):
        """Export report to HTML file"""
        html = self._generate_html_report(report)
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(html)
    
    def _generate_html_report(self, report: Dict) -> str:
        """Generate HTML report"""
        # Simple HTML template
        html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>API Security Report</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; }}
                h1 {{ color: #333; }}
                table {{ border-collapse: collapse; width: 100%; margin: 20px 0; }}
                th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
                th {{ background-color: #4CAF50; color: white; }}
                .critical {{ color: #d32f2f; }}
                .high {{ color: #f57c00; }}
                .medium {{ color: #fbc02d; }}
                .low {{ color: #388e3c; }}
            </style>
        </head>
        <body>
            <h1>API Security Report</h1>
            <p>Generated: {report.get('generated_at', 'N/A')}</p>
            <pre>{json.dumps(report, indent=2)}</pre>
        </body>
        </html>
        """
        return html


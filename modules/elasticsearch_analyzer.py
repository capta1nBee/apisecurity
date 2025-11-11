"""
Elasticsearch Analyzer Module
Analyzes API traffic logs from Elasticsearch
"""

import requests
from requests.auth import HTTPBasicAuth
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple
from collections import defaultdict
import os


class ElasticsearchAnalyzer:
    """Analyzes Elasticsearch traffic logs"""

    def __init__(self, es_url: str, username: Optional[str], password: Optional[str],
                 index_pattern: str, sensitive_keywords_file: str = 'sample.txt'):
        """Initialize Elasticsearch connection"""
        self.es_url = es_url
        self.auth = HTTPBasicAuth(username, password) if username and password else None
        self.index_pattern = index_pattern
        self.sensitive_keywords_file = sensitive_keywords_file

    def test_connection(self) -> bool:
        """Test Elasticsearch connection"""
        try:
            response = requests.get(self.es_url, auth=self.auth, timeout=5)
            return response.status_code == 200
        except:
            return False
    
    def get_traffic_stats(self, start_date: datetime, end_date: datetime, 
                         api_id: Optional[str] = None) -> Dict:
        """
        Get traffic statistics for date range
        
        Args:
            start_date: Start date for analysis
            end_date: End date for analysis
            api_id: Optional API ID to filter by
            
        Returns:
            Dictionary with traffic statistics
        """
        # Build query
        query = {
            "size": 0,
            "query": {
                "bool": {
                    "must": [
                        {
                            "range": {
                                "@timestamp": {
                                    "gte": start_date.strftime('%Y-%m-%dT%H:%M:%S.000Z'),
                                    "lte": end_date.strftime('%Y-%m-%dT%H:%M:%S.000Z')
                                }
                            }
                        }
                    ]
                }
            },
            "aggs": {
                "apis": {
                    "terms": {
                        "field": "api",
                        "size": 10000
                    },
                    "aggs": {
                        "api_name": {"terms": {"field": "apn", "size": 1}},
                        "environment": {"terms": {"field": "ei", "size": 100}},
                        "by_hour": {
                            "date_histogram": {
                                "field": "@timestamp",
                                "fixed_interval": "1h"
                            }
                        },
                        "unique_ips": {"cardinality": {"field": "hr1ra.keyword"}},
                        "unique_users": {"cardinality": {"field": "uok.keyword"}},
                        "top_ips": {"terms": {"field": "hr1ra.keyword", "size": 10}},
                        "top_users": {"terms": {"field": "uok.keyword", "size": 10}},
                        "avg_response_time": {"avg": {"field": "trt"}},
                        "status_codes": {"terms": {"field": "sc", "size": 20}},
                        "error_count": {
                            "filter": {
                                "range": {
                                    "sc": {
                                        "gte": 400
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        
        # Add API filter if specified
        if api_id:
            query["query"]["bool"]["must"].append({
                "term": {"api": api_id}
            })
        
        # Execute query
        url = f"{self.es_url}/.ds-{self.index_pattern}-*/_search"
        try:
            response = requests.post(url, json=query, auth=self.auth, timeout=60)
            response.raise_for_status()
            result = response.json()
            
            # Parse results
            return self._parse_traffic_stats(result, start_date, end_date)
        except Exception as e:
            print(f"Error querying Elasticsearch: {e}")
            try:
                print(f"Response content: {response.text[:500]}")
            except:
                pass
            return {}
    
    def _parse_traffic_stats(self, es_result: Dict, start_date: datetime, 
                            end_date: datetime) -> Dict:
        """Parse Elasticsearch aggregation results"""
        stats = {}
        
        total_hits = es_result.get('hits', {}).get('total', {}).get('value', 0)
        api_buckets = es_result.get('aggregations', {}).get('apis', {}).get('buckets', [])
        
        for bucket in api_buckets:
            api_id = bucket.get('key')
            total_requests = bucket.get('doc_count', 0)
            
            # Get API name
            api_name_buckets = bucket.get('api_name', {}).get('buckets', [])
            api_name = api_name_buckets[0].get('key') if api_name_buckets else 'Unknown'
            
            # Calculate time-based stats
            hours_diff = max((end_date - start_date).total_seconds() / 3600, 1)
            avg_requests_per_hour = total_requests / hours_diff
            
            # Get hourly distribution
            hourly_buckets = bucket.get('by_hour', {}).get('buckets', [])
            max_requests_per_hour = max([b.get('doc_count', 0) for b in hourly_buckets]) if hourly_buckets else 0
            
            # Estimate max per minute (from max hour / 60 * 1.5 burst factor)
            max_requests_per_minute = int(max_requests_per_hour / 60.0 * 1.5) if max_requests_per_hour > 0 else 0
            
            # Get peak hour
            peak_hour = None
            if hourly_buckets:
                peak_bucket = max(hourly_buckets, key=lambda x: x.get('doc_count', 0))
                peak_hour = peak_bucket.get('key_as_string')
            
            # Get unique counts
            unique_ips = bucket.get('unique_ips', {}).get('value', 0)
            unique_users = bucket.get('unique_users', {}).get('value', 0)
            
            # Get top consumers
            top_ips = [(b.get('key'), b.get('doc_count')) 
                      for b in bucket.get('top_ips', {}).get('buckets', [])]
            top_users = [(b.get('key'), b.get('doc_count')) 
                        for b in bucket.get('top_users', {}).get('buckets', [])]
            
            # Get response time
            avg_response_time = bucket.get('avg_response_time', {}).get('value', 0)
            
            # Get status codes
            status_codes = {}
            for sc_bucket in bucket.get('status_codes', {}).get('buckets', []):
                status_codes[sc_bucket.get('key')] = sc_bucket.get('doc_count', 0)
            
            # Get error count
            error_count = bucket.get('error_count', {}).get('doc_count', 0)
            error_rate = (error_count / total_requests * 100) if total_requests > 0 else 0
            
            # Calculate hourly distribution for peak hours
            hourly_distribution = defaultdict(int)
            for hour_bucket in hourly_buckets:
                timestamp = hour_bucket.get('key_as_string', '')
                count = hour_bucket.get('doc_count', 0)
                if timestamp:
                    try:
                        if 'T' in timestamp:
                            hour = int(timestamp.split('T')[1].split(':')[0])
                        else:
                            hour = int(timestamp.split(' ')[1].split(':')[0])
                        hourly_distribution[hour] += count
                    except:
                        pass
            
            # Find peak hours (top 5)
            peak_hours = []
            if hourly_distribution:
                sorted_hours = sorted(hourly_distribution.items(), key=lambda x: x[1], reverse=True)
                peak_hours = [h for h, c in sorted_hours[:5]]
            
            stats[api_id] = {
                'api_name': api_name,
                'total_requests': total_requests,
                'avg_requests_per_hour': round(avg_requests_per_hour, 2),
                'max_requests_per_hour': max_requests_per_hour,
                'max_requests_per_minute': max_requests_per_minute,
                'peak_hour': peak_hour,
                'peak_hours': sorted(peak_hours),
                'unique_ips': int(unique_ips),
                'unique_users': int(unique_users),
                'top_ips': top_ips[:5],
                'top_users': top_users[:5],
                'avg_response_time_ms': round(avg_response_time, 2) if avg_response_time else 0,
                'status_codes': status_codes,
                'error_count': error_count,
                'error_rate': round(error_rate, 2),
                'success_rate': round(100 - error_rate, 2)
            }
        
        return stats
    
    def get_api_traffic_timeline(self, api_id: str, start_date: datetime, 
                                 end_date: datetime, interval: str = '1h') -> List[Dict]:
        """
        Get traffic timeline for a specific API
        
        Args:
            api_id: API ID
            start_date: Start date
            end_date: End date
            interval: Time interval (1m, 5m, 1h, 1d)
            
        Returns:
            List of timeline data points
        """
        query = {
            "size": 0,
            "query": {
                "bool": {
                    "must": [
                        {"term": {"api": api_id}},
                        {
                            "range": {
                                "@timestamp": {
                                    "gte": start_date.strftime('%Y-%m-%dT%H:%M:%S.000Z'),
                                    "lte": end_date.strftime('%Y-%m-%dT%H:%M:%S.000Z')
                                }
                            }
                        }
                    ]
                }
            },
            "aggs": {
                "timeline": {
                    "date_histogram": {
                        "field": "@timestamp",
                        "fixed_interval": interval
                    },
                    "aggs": {
                        "avg_response_time": {"avg": {"field": "trt"}},
                        "error_count": {
                            "filter": {
                                "range": {"sc": {"gte": 400}}
                            }
                        }
                    }
                }
            }
        }
        
        url = f"{self.es_url}/.ds-{self.index_pattern}-*/_search"
        try:
            response = requests.post(url, json=query, auth=self.auth, timeout=60)
            response.raise_for_status()
            result = response.json()
            
            timeline = []
            for bucket in result.get('aggregations', {}).get('timeline', {}).get('buckets', []):
                timeline.append({
                    'timestamp': bucket.get('key_as_string'),
                    'requests': bucket.get('doc_count', 0),
                    'avg_response_time': bucket.get('avg_response_time', {}).get('value', 0),
                    'errors': bucket.get('error_count', {}).get('doc_count', 0)
                })
            
            return timeline
        except Exception as e:
            print(f"Error getting timeline: {e}")
            return []

    def check_sensitive_fields(self, api_id: str, sample_size: int = 1000) -> Dict:
        """
        Check if sensitive keywords exist in fcrh/fcrb fields
        Reads sensitive keywords from configured file (default: sample.txt)
        """
        try:
            # Read sensitive keywords from configured file
            sensitive_keywords = []

            # Support both absolute and relative paths
            if os.path.isabs(self.sensitive_keywords_file):
                sample_file = self.sensitive_keywords_file
            else:
                # Relative to project root
                sample_file = os.path.join(os.path.dirname(os.path.dirname(__file__)), self.sensitive_keywords_file)

            if os.path.exists(sample_file):
                with open(sample_file, 'r', encoding='utf-8') as f:
                    # Support both line-separated and comma-separated formats
                    content = f.read().strip()
                    if ',' in content:
                        # Comma-separated format: tc,kimlik,tel,numara
                        sensitive_keywords = [kw.strip().lower() for kw in content.split(',') if kw.strip()]
                    else:
                        # Line-separated format (one keyword per line)
                        sensitive_keywords = [line.strip().lower() for line in content.split('\n') if line.strip()]
            else:
                # Default sensitive keywords if file doesn't exist
                print(f"Warning: Sensitive keywords file not found: {sample_file}")
                sensitive_keywords = ['tc', 'kimlik', 'tel', 'telefon', 'sifre', 'password']

            # Query last N logs for this API - get fcrh and fcrb fields
            # Note: 'api' field is already keyword type, no .keyword suffix needed
            query = {
                "size": sample_size,
                "query": {
                    "bool": {
                        "must": [
                            {"term": {"api": api_id}}
                        ]
                    }
                },
                "sort": [{"@timestamp": "desc"}],
                "_source": ["fcrh", "fcrb", "@timestamp"]
            }

            response = requests.post(
                f"{self.es_url}/{self.index_pattern}/_search",
                auth=self.auth,
                json=query,
                headers={'Content-Type': 'application/json'}
            )

            if response.status_code != 200:
                return {
                    'error': f"ES query failed: {response.status_code}",
                    'total_logs': 0,
                    'sensitive_keywords_found': {}
                }

            result = response.json()
            hits = result.get('hits', {}).get('hits', [])
            total_logs = len(hits)

            # Count how many logs contain each sensitive keyword in fcrh or fcrb
            keyword_counts = {keyword: {'count': 0, 'in_headers': 0, 'in_body': 0} for keyword in sensitive_keywords}

            for hit in hits:
                source = hit.get('_source', {})
                fcrh = str(source.get('fcrh', '')).lower()
                fcrb = str(source.get('fcrb', '')).lower()

                for keyword in sensitive_keywords:
                    found_in_headers = keyword in fcrh
                    found_in_body = keyword in fcrb

                    if found_in_headers or found_in_body:
                        keyword_counts[keyword]['count'] += 1
                        if found_in_headers:
                            keyword_counts[keyword]['in_headers'] += 1
                        if found_in_body:
                            keyword_counts[keyword]['in_body'] += 1

            # Calculate percentages
            keyword_percentages = {}
            for keyword, counts in keyword_counts.items():
                if counts['count'] > 0:
                    percentage = (counts['count'] / total_logs * 100) if total_logs > 0 else 0
                    keyword_percentages[keyword] = {
                        'count': counts['count'],
                        'percentage': round(percentage, 2),
                        'in_headers': counts['in_headers'],
                        'in_body': counts['in_body'],
                        'exists': True
                    }

            return {
                'total_logs_checked': total_logs,
                'sensitive_keywords': keyword_percentages,
                'has_sensitive_data': len(keyword_percentages) > 0
            }
        except Exception as e:
            print(f"Error checking sensitive fields: {e}")
            return {
                'error': str(e),
                'total_logs_checked': 0,
                'sensitive_keywords': {},
                'has_sensitive_data': False
            }

    def get_hourly_traffic_distribution(self, start_date: datetime, end_date: datetime, api_id: str) -> Dict:
        """
        Get traffic distribution by hour (0-23) for heatmap visualization
        """
        try:
            # Use date_histogram and group by hour of day
            # Note: 'api' field is already keyword type, no .keyword suffix needed
            query = {
                "size": 0,
                "query": {
                    "bool": {
                        "must": [
                            {"term": {"api": api_id}},
                            {
                                "range": {
                                    "@timestamp": {
                                        "gte": start_date.strftime('%Y-%m-%dT%H:%M:%S.000Z'),
                                        "lte": end_date.strftime('%Y-%m-%dT%H:%M:%S.000Z')
                                    }
                                }
                            }
                        ]
                    }
                },
                "aggs": {
                    "by_hour": {
                        "date_histogram": {
                            "field": "@timestamp",
                            "calendar_interval": "hour"
                        }
                    }
                }
            }

            response = requests.post(
                f"{self.es_url}/{self.index_pattern}/_search",
                auth=self.auth,
                json=query,
                headers={'Content-Type': 'application/json'}
            )

            if response.status_code != 200:
                print(f"ES query failed: {response.status_code} - {response.text}")
                return {'hourly_distribution': [0] * 24, 'max_traffic': 0, 'total_requests': 0}

            result = response.json()

            # Initialize 24-hour array
            hourly_counts = [0] * 24

            # Aggregate by hour of day (0-23)
            for bucket in result.get('aggregations', {}).get('by_hour', {}).get('buckets', []):
                timestamp = bucket.get('key_as_string', '')
                count = bucket.get('doc_count', 0)

                if timestamp:
                    try:
                        # Extract hour from timestamp (format: 2025-11-10T14:00:00.000Z)
                        if 'T' in timestamp:
                            hour = int(timestamp.split('T')[1].split(':')[0])
                            if 0 <= hour < 24:
                                hourly_counts[hour] += count
                    except Exception as e:
                        print(f"Error parsing timestamp {timestamp}: {e}")

            max_traffic = max(hourly_counts) if hourly_counts else 0

            return {
                'hourly_distribution': hourly_counts,
                'max_traffic': max_traffic,
                'total_requests': sum(hourly_counts)
            }
        except Exception as e:
            print(f"Error getting hourly distribution: {e}")
            import traceback
            traceback.print_exc()
            return {'hourly_distribution': [0] * 24, 'max_traffic': 0, 'total_requests': 0}


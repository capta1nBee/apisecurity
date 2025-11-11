"""
API Security Dashboard - Flask Application
API security monitoring and analysis
"""

from flask import Flask, render_template, request, jsonify, send_file
from flask_cors import CORS
from datetime import datetime, timedelta
from typing import Dict, List
import os
import io

from config import config
from modules import (
    ElasticsearchAnalyzer,
    MongoDBAnalyzer,
    SecurityScorer,
    ReportExporter
)

# Initialize Flask app
app = Flask(__name__)
env = os.environ.get('FLASK_ENV', 'development')
app.config.from_object(config[env])
CORS(app)

# Global analyzers (initialized on first request)
mongodb_analyzer = None
es_analyzers = {}


def get_mongodb_analyzer():
    """Get or create MongoDB analyzer"""
    global mongodb_analyzer
    if mongodb_analyzer is None:
        mongodb_analyzer = MongoDBAnalyzer(
            app.config['MONGODB_URI'],
            app.config['MONGODB_DB']
        )
    return mongodb_analyzer


def get_es_analyzers():
    """Get or create Elasticsearch analyzers from MongoDB"""
    global es_analyzers
    if not es_analyzers:
        # Get MongoDB analyzer to fetch ES configs
        mongo = get_mongodb_analyzer()
        es_configs = mongo.get_elasticsearch_configs()

        # Create ES analyzers from MongoDB configs
        for es_config in es_configs:
            # Only use authentication if authenticate flag is True
            username = es_config['username'] if es_config.get('authenticate', False) else None
            password = es_config['password'] if es_config.get('authenticate', False) else None

            es_analyzers[es_config['name']] = ElasticsearchAnalyzer(
                es_config['url'],
                username,
                password,
                es_config['index_pattern'],
                app.config['SENSITIVE_KEYWORDS_FILE']
            )
    return es_analyzers


@app.route('/')
def index():
    """Dashboard home page"""
    return render_template('dashboard.html')


@app.route('/api/<api_id>')
def api_detail_page(api_id):
    """API detail page"""
    mongo = get_mongodb_analyzer()
    api_details = mongo.get_api_details(api_id)

    if not api_details:
        return "API not found", 404

    return render_template('api_detail.html',
                         api_id=api_id,
                         api_name=api_details['service_name'])


@app.route('/api/overview')
def api_overview():
    """Get overview statistics - Fast, MongoDB only, no ES queries"""
    try:
        mongo = get_mongodb_analyzer()

        # Get security statistics from MongoDB only (fast)
        stats = mongo.get_security_statistics()

        return jsonify({
            'success': True,
            'data': {
                'total_apis': stats['total_apis'],
                'with_security': stats['with_security'],
                'with_throttling': stats['with_throttling'],
                'with_auth': stats['with_auth'],
                'security_percentage': stats['security_percentage'],
                'throttling_percentage': stats['throttling_percentage'],
                'auth_percentage': stats['auth_percentage']
            }
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@app.route('/api/apis')
def get_apis():
    """Get list of APIs with basic info"""
    try:
        mongo = get_mongodb_analyzer()
        apis = mongo.get_api_list()
        
        return jsonify({
            'success': True,
            'data': apis
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@app.route('/api/apis/<api_id>')
def get_api_detail(api_id):
    """Get detailed information about a specific API"""
    try:
        mongo = get_mongodb_analyzer()
        api_details = mongo.get_api_details(api_id)
        
        if not api_details:
            return jsonify({
                'success': False,
                'error': 'API not found'
            }), 404
        
        return jsonify({
            'success': True,
            'data': api_details
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@app.route('/api/apis/<api_id>/score')
def get_api_score(api_id):
    """
    Get security score for an API
    Query params:
        - start_date: Start date (ISO format)
        - end_date: End date (ISO format)
        - es_name: Elasticsearch name (PROD-ES, TEST-ES)
    """
    try:
        # Parse date range
        end_date = datetime.now()
        start_date = end_date - timedelta(days=app.config['DEFAULT_DATE_RANGE_DAYS'])
        
        if request.args.get('start_date'):
            start_date = datetime.fromisoformat(request.args.get('start_date'))
        if request.args.get('end_date'):
            end_date = datetime.fromisoformat(request.args.get('end_date'))
        
        # Get ES name
        es_name = request.args.get('es_name', 'PROD-ES')
        
        # Get analyzers
        mongo = get_mongodb_analyzer()
        es_analyzers_dict = get_es_analyzers()
        
        if es_name not in es_analyzers_dict:
            return jsonify({
                'success': False,
                'error': f'Elasticsearch {es_name} not found'
            }), 404
        
        es_analyzer = es_analyzers_dict[es_name]
        
        # Get API configuration
        api_config = mongo.get_api_details(api_id)
        if not api_config:
            return jsonify({
                'success': False,
                'error': 'API not found'
            }), 404
        
        # Get traffic statistics
        traffic_stats_dict = es_analyzer.get_traffic_stats(start_date, end_date, api_id)
        traffic_stats = traffic_stats_dict.get(api_id, {})

        # Check for sensitive data in logs (always check, regardless of trace logging)
        sensitive_data = es_analyzer.check_sensitive_fields(api_id, sample_size=1000)
        traffic_stats['sensitive_data'] = sensitive_data

        # Calculate security score
        scorer = SecurityScorer(app.config['SECURITY_SCORE_WEIGHTS'])
        score_result = scorer.calculate_api_score(api_config, traffic_stats)
        
        return jsonify({
            'success': True,
            'data': {
                'api_id': api_id,
                'api_name': api_config['service_name'],
                'date_range': {
                    'start': start_date.isoformat(),
                    'end': end_date.isoformat()
                },
                'elasticsearch': es_name,
                'score': score_result,
                'traffic_stats': traffic_stats,
                'policies': api_config.get('policies', {}),  # Add policies from MongoDB
                'backend_ssl': api_config.get('backend_ssl', {}),  # Add backend SSL info
                'client_ssl': api_config.get('client_ssl', {}),  # Add client SSL info
                'logs_enabled': api_config.get('logs_enabled', {})  # Add logs enabled info
            }
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@app.route('/api/traffic/stats')
def get_traffic_stats():
    """
    Get traffic statistics for all APIs or specific API
    Query params:
        - start_date: Start date (ISO format)
        - end_date: End date (ISO format)
        - es_name: Elasticsearch name
        - api_id: Optional API ID filter
    """
    try:
        # Parse parameters
        end_date = datetime.now()
        start_date = end_date - timedelta(days=app.config['DEFAULT_DATE_RANGE_DAYS'])
        
        if request.args.get('start_date'):
            start_date = datetime.fromisoformat(request.args.get('start_date'))
        if request.args.get('end_date'):
            end_date = datetime.fromisoformat(request.args.get('end_date'))
        
        es_name = request.args.get('es_name', 'PROD-ES')
        api_id = request.args.get('api_id')
        
        # Get ES analyzer
        es_analyzers_dict = get_es_analyzers()
        if es_name not in es_analyzers_dict:
            return jsonify({
                'success': False,
                'error': f'Elasticsearch {es_name} not found'
            }), 404
        
        es_analyzer = es_analyzers_dict[es_name]
        
        # Get traffic stats
        traffic_stats = es_analyzer.get_traffic_stats(start_date, end_date, api_id)
        
        return jsonify({
            'success': True,
            'data': {
                'date_range': {
                    'start': start_date.isoformat(),
                    'end': end_date.isoformat()
                },
                'elasticsearch': es_name,
                'stats': traffic_stats
            }
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@app.route('/api/traffic/timeline/<api_id>')
def get_traffic_timeline(api_id):
    """
    Get traffic timeline for an API
    Query params:
        - start_date, end_date, es_name, interval
    """
    try:
        # Parse parameters
        end_date = datetime.now()
        start_date = end_date - timedelta(days=1)
        
        if request.args.get('start_date'):
            start_date = datetime.fromisoformat(request.args.get('start_date'))
        if request.args.get('end_date'):
            end_date = datetime.fromisoformat(request.args.get('end_date'))
        
        es_name = request.args.get('es_name', 'PROD-ES')
        interval = request.args.get('interval', '1h')
        
        # Get ES analyzer
        es_analyzers_dict = get_es_analyzers()
        if es_name not in es_analyzers_dict:
            return jsonify({
                'success': False,
                'error': f'Elasticsearch {es_name} not found'
            }), 404
        
        es_analyzer = es_analyzers_dict[es_name]
        
        # Get timeline
        timeline = es_analyzer.get_api_traffic_timeline(api_id, start_date, end_date, interval)
        
        return jsonify({
            'success': True,
            'data': {
                'api_id': api_id,
                'timeline': timeline
            }
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@app.route('/health')
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.now().isoformat()
    })


@app.errorhandler(404)
def not_found(error):
    """404 error handler"""
    return jsonify({
        'success': False,
        'error': 'Not found'
    }), 404


@app.route('/api/apis/<api_id>/sensitive-fields')
def check_sensitive_fields(api_id):
    """
    Check if sensitive fields exist in logs
    Query params:
        - es_name: Elasticsearch name (default: PROD-ES)
        - sample_size: Number of logs to check (default: 1000)
    """
    try:
        es_name = request.args.get('es_name', 'PROD-ES')
        sample_size = int(request.args.get('sample_size', 1000))

        # Get ES analyzer
        es_analyzers_dict = get_es_analyzers()
        if es_name not in es_analyzers_dict:
            return jsonify({
                'success': False,
                'error': f'Elasticsearch {es_name} not found'
            }), 404

        es_analyzer = es_analyzers_dict[es_name]

        # Check sensitive fields
        result = es_analyzer.check_sensitive_fields(api_id, sample_size)

        return jsonify({
            'success': True,
            'data': result
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@app.route('/api/apis/<api_id>/hourly-distribution')
def get_hourly_distribution(api_id):
    """
    Get hourly traffic distribution for heatmap
    Query params:
        - start_date: Start date (ISO format)
        - end_date: End date (ISO format)
        - es_name: Elasticsearch name (default: PROD-ES)
    """
    try:
        # Parse date range
        end_date = datetime.now()
        start_date = end_date - timedelta(days=app.config['DEFAULT_DATE_RANGE_DAYS'])

        if request.args.get('start_date'):
            start_date = datetime.fromisoformat(request.args.get('start_date'))
        if request.args.get('end_date'):
            end_date = datetime.fromisoformat(request.args.get('end_date'))

        es_name = request.args.get('es_name', 'PROD-ES')

        # Get ES analyzer
        es_analyzers_dict = get_es_analyzers()
        if es_name not in es_analyzers_dict:
            return jsonify({
                'success': False,
                'error': f'Elasticsearch {es_name} not found'
            }), 404

        es_analyzer = es_analyzers_dict[es_name]

        # Get hourly distribution
        result = es_analyzer.get_hourly_traffic_distribution(start_date, end_date, api_id)

        return jsonify({
            'success': True,
            'data': result
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@app.route('/api/apis/<api_id>/export/<format>')
def export_report(api_id, format):
    """
    Export security report in PDF or Excel format
    Query params:
        - start_date: Start date (ISO format)
        - end_date: End date (ISO format)
        - es_name: Elasticsearch name (default: PROD-ES)
    """
    try:
        # Validate format
        if format not in ['pdf', 'excel']:
            return jsonify({
                'success': False,
                'error': 'Invalid format. Use pdf or excel'
            }), 400

        # Parse date range
        end_date = datetime.now()
        start_date = end_date - timedelta(days=app.config['DEFAULT_DATE_RANGE_DAYS'])

        if request.args.get('start_date'):
            start_date = datetime.fromisoformat(request.args.get('start_date'))
        if request.args.get('end_date'):
            end_date = datetime.fromisoformat(request.args.get('end_date'))

        es_name = request.args.get('es_name', 'PROD-ES')

        # Get analyzers
        mongo = get_mongodb_analyzer()
        es_analyzers_dict = get_es_analyzers()

        if es_name not in es_analyzers_dict:
            return jsonify({
                'success': False,
                'error': f'Elasticsearch {es_name} not found'
            }), 404

        es_analyzer = es_analyzers_dict[es_name]

        # Get API configuration
        api_config = mongo.get_api_details(api_id)
        if not api_config:
            return jsonify({
                'success': False,
                'error': 'API not found'
            }), 404

        # Get traffic statistics
        traffic_stats_dict = es_analyzer.get_traffic_stats(start_date, end_date, api_id)
        traffic_stats = traffic_stats_dict.get(api_id, {})

        # Check for sensitive data
        sensitive_data = es_analyzer.check_sensitive_fields(api_id, sample_size=1000)
        traffic_stats['sensitive_data'] = sensitive_data

        # Calculate security score
        scorer = SecurityScorer(app.config['SECURITY_SCORE_WEIGHTS'])
        score_result = scorer.calculate_api_score(api_config, traffic_stats)

        # Prepare report data
        report_data = {
            'api_id': api_id,
            'api_name': api_config['service_name'],
            'date_range': {
                'start': start_date.strftime('%Y-%m-%d'),
                'end': end_date.strftime('%Y-%m-%d')
            },
            'elasticsearch': es_name,
            'score': score_result,
            'weights': app.config['SECURITY_SCORE_WEIGHTS'],
            'traffic_stats': traffic_stats
        }

        # Export report
        exporter = ReportExporter()

        if format == 'pdf':
            pdf_bytes = exporter.export_to_pdf(report_data)
            filename = f"security_report_{api_config['service_name']}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"

            return send_file(
                io.BytesIO(pdf_bytes),
                mimetype='application/pdf',
                as_attachment=True,
                download_name=filename
            )
        else:  # excel
            excel_bytes = exporter.export_to_excel(report_data)
            filename = f"security_report_{api_config['service_name']}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.xlsx"

            return send_file(
                io.BytesIO(excel_bytes),
                mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
                as_attachment=True,
                download_name=filename
            )

    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@app.route('/api/apis/<api_id>/share', methods=['POST'])
def share_report(api_id):
    """
    Generate shareable link for the report
    Body params:
        - start_date: Start date (ISO format)
        - end_date: End date (ISO format)
        - es_name: Elasticsearch name
        - email: Optional email to send report to
    """
    try:
        data = request.get_json()

        # Get API details
        mongo = get_mongodb_analyzer()
        api_config = mongo.get_api_details(api_id)

        if not api_config:
            return jsonify({
                'success': False,
                'error': 'API not found'
            }), 404

        # Generate shareable URL
        base_url = request.host_url.rstrip('/')
        start_date = data.get('start_date', (datetime.now() - timedelta(days=7)).strftime('%Y-%m-%d'))
        end_date = data.get('end_date', datetime.now().strftime('%Y-%m-%d'))
        es_name = data.get('es_name', 'PROD-ES')

        share_url = f"{base_url}/api/{api_id}?start_date={start_date}&end_date={end_date}&es_name={es_name}"

        # If email is provided, send report (placeholder for now)
        email = data.get('email')
        email_sent = False

        if email:
            # TODO: Implement email sending functionality
            # For now, just return success
            email_sent = True

        return jsonify({
            'success': True,
            'data': {
                'share_url': share_url,
                'api_name': api_config['service_name'],
                'email_sent': email_sent,
                'email': email if email_sent else None
            }
        })

    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@app.errorhandler(500)
def internal_error(error):
    """500 error handler"""
    return jsonify({
        'success': False,
        'error': 'Internal server error'
    }), 500


if __name__ == '__main__':
    app.run(
        host='0.0.0.0',
        port=5000,
        debug=app.config['DEBUG']
    )


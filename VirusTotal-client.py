from flask import Flask, render_template, request, redirect, url_for, flash
import requests
import time
import secrets
import logging
import config

app = Flask(__name__)
app.secret_key = secrets.token_urlsafe(16)

@app.route('/')
def index():
    return render_template('home-page.html')

@app.route('/about-page.html')
def about():
    return render_template('about-page.html')

@app.route('/login-page.html')
def login():
    return render_template('login-page.html')

@app.route('/reset-pass.html')
def reset():
    return render_template('reset-pass.html')

@app.route('/resources-page.html')
def resources():
    return render_template('resources-page.html')

@app.route('/signup-page.html')
def signup():
    return render_template('signup-page.html')

@app.route('/upload', methods=['POST'])
def upload_file():
    if 'upload' not in request.files:
        flash('No file part')
        return redirect(request.url)
    
    file = request.files['upload']
    
    if file.filename == '':
        flash('No selected file')
        return redirect(request.url)
    
    if file:
        # Send the file to VirusTotal
        url = 'https://www.virustotal.com/api/v3/files'
        headers = {
            'x-apikey': config.VIRUSTOTAL_API_KEY
        }
        files = {'file': (file.filename, file.stream, file.content_type)}
        
        logging.debug('Uploading file to VirusTotal')
        response = requests.post(url, headers=headers, files=files)
        
        if response.status_code == 200:
            analysis_id = response.json()['data']['id']
            logging.debug(f'File uploaded successfully, analysis ID: {analysis_id}')
            
            # Fetch the scan results
            analysis_url = f'https://www.virustotal.com/api/v3/analyses/{analysis_id}'
            
            retries = 10
            while retries > 0:
                logging.debug(f'Fetching analysis results, retries left: {retries}')
                analysis_response = requests.get(analysis_url, headers=headers)

                if analysis_response.status_code == 200:
                    analysis_data = analysis_response.json()
                    status = analysis_data['data']['attributes']['status']
                    logging.debug(f'Analysis status: {status}')

                    if status == 'completed':
                    # Count the number of malicious detections
                        malicious_count = 0
                        scans = analysis_data['data']['attributes']['results']
                        for engine, result in scans.items():
                            if result['category'] == 'malicious':
                                malicious_count += 1
                    
                    # Fetch the behavior data
                        sha256 = analysis_data['meta']['file_info']['sha256']
                        behavior_url = f'https://www.virustotal.com/api/v3/files/{sha256}/behaviour_summary'
                        logging.debug(f'Fetching behavior data for SHA256: {sha256}')
                        behavior_response = requests.get(behavior_url, headers=headers)

                        if behavior_response.status_code == 200:
                            behavior_data = behavior_response.json()
                            if behavior_data and 'data' in behavior_data and behavior_data['data'] and 'signature_matches' in behavior_data['data']:
                                logging.debug('Behavior data retrieved successfully')
                                for behavior in behavior_data['data']['signature_matches']:
                                    severity = behavior.get('severity')
                                    if severity == 'IMPACT_SEVERITY_HIGH':
                                        behavior['severity'] = 'HIGH'
                                    elif severity == 'IMPACT_SEVERITY_MEDIUM':
                                        behavior['severity'] = 'MEDIUM'
                                    elif severity == 'IMPACT_SEVERITY_LOW':
                                        behavior['severity'] = 'LOW'
                                    elif severity == 'IMPACT_SEVERITY_INFO':
                                        behavior['severity'] = 'INFO'
                                return render_template('result.html', analysis_data=analysis_data, behavior_data=behavior_data, malicious_count=malicious_count)
                            else:
                                logging.error('Unexpected response structure for behavior data')
                                flash('Behavior data not available. Displaying scan results only.')
                                return render_template('result.html', analysis_data=analysis_data, behavior_data=None,malicious_count=malicious_count)
                        else:
                            logging.error(f'Failed to retrieve behavior data. Status Code: {behavior_response.status_code}')
                            logging.error(f'Behavior response: {behavior_response.json()}')
                            flash('Failed to retrieve behavior data. Displaying scan results only.')
                            return render_template('result.html', analysis_data=analysis_data, behavior_data=None, malicious_count=malicious_count)
                elif analysis_response.status_code == 404:
                    logging.error('Analysis not found.')
                    flash('Analysis not found.')
                    return redirect(url_for('index'))
                elif analysis_response.status_code == 429:
                    logging.error('Rate limit exceeded. Please try again later.')
                    flash('Rate limit exceeded. Please try again later.')
                    return redirect(url_for('index'))
                else:
                    logging.error(f'Failed to retrieve analysis. Status Code: {analysis_response.status_code}')
                    logging.error(f'Analysis response: {analysis_response.json()}')
                    flash(f'Failed to retrieve analysis. Status Code: {analysis_response.status_code}')
                    return redirect(url_for('index'))
                
                retries -= 1
                time.sleep(30)  # Wait for 30 seconds before retrying
        else:
            flash(f'Failed to upload file to VirusTotal. Status Code: {response.status_code}')
            return redirect(url_for('index'))

    flash('Unexpected error occurred.')
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run()
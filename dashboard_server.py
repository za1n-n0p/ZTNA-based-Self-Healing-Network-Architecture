from flask import Flask, send_from_directory
import ssl
import os

app = Flask(__name__, static_folder='.')

@app.route('/')
@app.route('/<path:path>')
def serve_static(path='dashboard.html'):
    return send_from_directory('.', path)

if __name__ == '__main__':
    context = ('cert.pem', 'key.pem')
    app.run(host='0.0.0.0', port=8080, ssl_context=context, debug=False)
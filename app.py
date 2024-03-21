from flask import Flask, render_template, request
from vul import scan_website

app = Flask(__name__)

@app.route('/', methods=['GET', 'POST'])
def index():
    vulnerabilities = []

    if request.method == 'POST':
        url = request.form['url']
        vulnerabilities = scan_website(url)

    return render_template('index.html', vulnerabilities=vulnerabilities)

if __name__ == '__main__':
    app.run(debug=True)

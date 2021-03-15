import os

from flask import Flask, render_template, request

from sources.reporter import mainReporter, ReporterPcap, ReporterFile
from werkzeug.utils import secure_filename

ALLOWED_EXTENSIONS = {'pcap'}
app = Flask(__name__)
app.config['UPLOAD_PATH'] = 'uploads'
app.jinja_options['extensions'].append('jinja2.ext.loopcontrols')
fileStrings = {}


@app.route('/')
@app.route('/submit')
def home():
    return render_template('home.html')


@app.route('/submit/ioc')
def iocSubmit():
    return render_template('iocsubmit.html')


@app.route('/submit/pcap')
def pcapSubmit():
    return render_template('pcapsubmit.html')


@app.route('/submit/file')
def fileSubmit():
    return render_template('filesubmit.html')


@app.route('/validate', methods=['POST'])
def validate():
    ioc = request.form['ioc']
    if ioc:
        reportsData = mainReporter(ioc)
        print('IOC DATA:', reportsData)
        if len(reportsData) > 0:
            return render_template('iocanalysis.html', result=reportsData)
        else:
            return render_template('empty.html', result='TRY AGAIN')
    else:
        return render_template('empty.html', result='NO VALUE ENTERED')


def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


@app.route('/pcap', methods=['POST'])
def pcapAnalyzer():
    if request.method == 'POST':
        abuse = request.form.get('abuse')
        virus = request.form.get('virus')
        urlscan = request.form.get('urlscan')
        countTable = request.form.get('countTable')
        bot = request.form.get('bot')
        url = request.form.get('urls')
        file = request.files['file']

        if file.filename == '' or not file:
            return render_template('empty.html', result='SUBMIT A FILE')

        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            if filename:
                abuseCheck = True if abuse == 'on' else False
                virusCheck = True if virus == 'on' else False
                urlscanCheck = True if urlscan == 'on' else False
                countTableCheck = True if countTable == 'on' else False
                botCheck = True if bot == 'on' else False
                urlCheck = True if url == 'on' else False

                data = ReporterPcap(file, abuseCheck, virusCheck, urlscanCheck, countTableCheck, botCheck, urlCheck)
                print('PCAP DATA:', data)
                if data.get('error'):
                    return render_template('empty.html', result=data.get('error'))

                if data.get('EngineData') or data.get('totalIp') or data.get('totalPub') or data.get(
                        'graph') or data.get('urls').get('urls'):
                    return render_template('pcapanalysis.html', result=data)
                else:
                    if data.get('error'):
                        return render_template('empty.html', result=data.get('error'))
                    elif not data.get('urls').get('urls'):
                        return render_template('empty.html', result='NO URLS FOUND')
                    else:
                        return render_template('empty.html', result='SELECT ANY OF THE CHECKBOXES')
            else:
                return render_template('empty.html', result='FILENAME SHOULD BE ASCII')
        else:
            return render_template('empty.html', result='SUBMIT PCAP FILE WITH EXTENSION .PCAP')
    else:
        return render_template('empty.html', result='SOMETHING WENT WRONG')


@app.route('/file/strings', methods=['GET'])
def fileStrings():
    return render_template('filestrings.html', result=fileStrings)


@app.route('/file', methods=['POST'])
def fileAnalyzer():
    if request.method == 'POST':
        strings = request.form.get('strings')
        ped = request.form.get('ped')
        engine = request.form.get('engine')
        global fileStrings
        uploaded_file = request.files['file']
        filename = secure_filename(uploaded_file.filename)
        if filename != '':
            directory_path = os.path.join(app.config['UPLOAD_PATH'], filename)
            if os.path.isfile(directory_path):
                data = ReporterFile(directory_path, strings, ped, engine)
                fileStrings = data
            else:
                uploaded_file.save(directory_path)
                data = ReporterFile(directory_path, strings, ped, engine)
                fileStrings = data
            print('FILE DATA:', data)
            return render_template('fileanalysis.html', result=data)
        else:
            return render_template('empty.html', result='SOMETHING WENT WRONG')


if __name__ == '__main__':
    app.run(host='127.0.0.1', port=5002, debug=True)

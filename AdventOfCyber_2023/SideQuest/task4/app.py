import os
import pycurl
from io import BytesIO
from flask_mysqldb import MySQL
import MySQLdb.cursors
from flask import Flask, send_from_directory, render_template, request, redirect, url_for, Response

app = Flask(__name__, static_url_path='/static')

# MySQL configuration
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'mcskidy'
app.config['MYSQL_PASSWORD'] = 'fSXT8582GcMLmSt6'
app.config['MYSQL_DB'] = 'elfimages'
mysql = MySQL(app)

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/download")
def download():
    file_id = request.args.get('id','')

    if file_id!='':
        cur = mysql.connection.cursor()
        query = "SELECT url FROM elves where url_id = '%s'" % (file_id)
        cur.execute(query)
        results = cur.fetchall()
        for url in results:
            filename = url[0]

            response_buf = BytesIO()
            crl = pycurl.Curl()
            crl.setopt(crl.URL, filename)
            crl.setopt(crl.WRITEDATA, response_buf)
            crl.perform()
            crl.close()
            file_data = response_buf.getvalue()

            resp = Response(file_data)
            resp.headers['Content-Type'] = 'image/svg+xml'
            resp.headers['Content-Disposition'] = 'attachment'
            return resp
    else:
        return 'No file selected... '

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=8000, debug=True)
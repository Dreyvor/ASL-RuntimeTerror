from flask import Flask, request
import requests

app = Flask(__name__)


@app.post("/login")
def login():
    # login using user ID and password and get a session token
    return {}, 200


@app.post("/login_certificate")
def login_certificate():
    # login using certificate and get a session token
    return {}, 200


@app.get("/user_data")
def get_user_data():
    # retrieve user data from database
    return {}, 200


@app.post("/user_data")
def update_user_data():
    # update user data in the database
    return {}, 200


@app.post("/issue_certificate")
def issue_certificate():
    # issue certificate based on user data
    return {}, 200


@app.get("/download_certificate")
def download_certificate():
    # get user's certificate and possibly private key (PKCS#12) and send it
    return {}, 200


@app.post("/revoke_certificate")
def revoke_certificate():
    # revoke certain certificate or all user's certificates
    return {}, 200


@app.get("/num_issued_certificates")
def num_issued_certificates():
    # get current number of issued certificates
    return {}, 200


@app.get("/num_revoked_certificates")
def num_revoked_certificates():
    # get current number of revoked certificates
    return {}, 200


@app.get("/certificate_serial_number")
def certificate_serial_number():
    # get current certificate serial number
    return {}, 200

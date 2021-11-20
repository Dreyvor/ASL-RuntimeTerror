from flask import Flask, request
import requests


class CAServerService:
    def __init__(self, ca_server_address):
        self.ca_server_address = ca_server_address

    def get_certificate(self, host, dns_names, oids=None):
        return requests.post(self.ca_server_address + "/get_certificate", {
            "ost": host,
            "dns_names": dns_names,
            "oids": oids
        })

    def revoke_certificate(self, host, common_name):
        return requests.post(self.ca_server_address + "/revoke_certificate", {
            "host": host,
            "common_name": common_name
        })

    def is_certificate_revoked(self, host):
        return requests.get(self.ca_server_address + "/is_certificate_revoked", params={"host": host})

    def root_ca_certificate(self):
        return requests.get(self.ca_server_address + "/root_ca_certificate")

    def intermediate_ca_certificate(self):
        return requests.get(self.ca_server_address + "/intermediate_ca_certificate")


app = Flask(__name__)
ca_service = CAServerService("http://192.168.10.10:5000")


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

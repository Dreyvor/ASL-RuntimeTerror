import os.path

from ownca import CertificateAuthority
from flask import Flask, request


class CAServer:

    def __init__(self, root_ca_storage_path='root-ca-storage', intermediate_ca_storage_path='intermediate-ca-storage'):
        self._root_ca = CertificateAuthority(ca_storage=root_ca_storage_path, common_name="Root CA")
        if not os.path.exists(os.path.join(root_ca_storage_path, 'certs', 'Intermediate CA')):
            self._intermediate_ca = CertificateAuthority(ca_storage=intermediate_ca_storage_path, common_name="Intermediate CA", intermediate=True)
            intermediate_ca_certificate = self._root_ca.sign_csr(self._intermediate_ca.csr, self._intermediate_ca.public_key)
            with open(os.path.join(intermediate_ca_storage_path, 'ca.crt'), 'wb') as cert_file:
                cert_file.write(intermediate_ca_certificate.cert_bytes)
        self._intermediate_ca = CertificateAuthority(ca_storage=intermediate_ca_storage_path, common_name="Intermediate CA")
        self._intermediate_ca_certificate = self._intermediate_ca.cert

    def get_root_ca_certificate(self):
        return self._root_ca.cert_bytes.decode("utf-8")

    def get_intermediate_ca_certificate(self):
        return self._intermediate_ca.cert_bytes.decode("utf-8")

    def issue_certificate(self, host_name, dns_names, oids):
        return self._intermediate_ca.issue_certificate(host_name, dns_names=dns_names, oids=oids)

    def revoke_certificate(self, host_name, common_name):
        self._intermediate_ca.revoke_certificate(host_name, common_name)
        return "Certificate for " + host_name + " is now revoked"

    def is_certificate_revoked(self, host_name):
        return self._intermediate_ca.load_certificate(host_name).revoked


app = Flask(__name__)
ca_server: CAServer = CAServer()


@app.post('/get_certificate')
def get_certificate():
    data = request.get_json()
    cert = ca_server.issue_certificate(data['host'], data['dns_names'], data['oids'] if 'oids' in data else None)
    response = {
        'cert': cert.cert_bytes.decode("utf-8"),
        'cert_private_key': cert.key_bytes.decode("utf-8"),
        'cert_public_key': cert.public_key_bytes.decode("utf-8"),
        'cert_common_name': cert.common_name
    }
    return response, 200


@app.post('/revoke_certificate')
def revoke_certificate():
    data = request.get_json()
    message = ca_server.revoke_certificate(data['host'], data['common_name'])
    return {'message': message}, 200


@app.get('/is_certificate_revoked')
def is_certificate_revoked():
    host = request.args.get('host')
    message = ca_server.is_certificate_revoked(host)
    return {'message': message}, 200


@app.get('/root_ca_certificate')
def get_root_ca_certificate():
    certificate = ca_server.get_root_ca_certificate()
    return {'certificate': certificate}, 200


@app.get('/intermediate_ca_certificate')
def get_intermediate_ca_certificate():
    certificate = ca_server.get_intermediate_ca_certificate()
    return {'certificate': certificate}, 200

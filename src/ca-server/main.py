from ownca import CertificateAuthority
from flask import Flask, request


class CAServer:

    def __init__(self, storage_path, name):
        self._ca = CertificateAuthority(ca_storage=storage_path, common_name=name)

    def issue_certificate(self, host_name, dns_names):
        return self._ca.issue_certificate(host_name, dns_names=dns_names)

    def revoke_certificate(self, host_name, common_name):
        updated_ca = self._ca.revoke_certificate(host_name, common_name)
        if updated_ca is None:
            return "The certificate has already been revoked"
        else:
            self._ca = updated_ca
            return "The certificate is now revoked"


app = Flask(__name__)
ca_server: CAServer = CAServer('ca-storage', 'Root CA')


@app.post('/get_certificate')
def get_certificate():
    data = request.get_json()
    cert = ca_server.issue_certificate(data['host'], data['dns_names'])
    response = {
        'cert': cert.cert_bytes.decode("utf-8"),
        'cert_private_key': cert.key_bytes.decode("utf-8"),
        'cert_public_key': cert.public_key_bytes.decode("utf-8"),
        'cert_csr': cert.csr_bytes.decode("utf-8"),
        'cert_common_name': cert.common_name
    }
    return response, 200


@app.post('/revoke_certificate')
def revoke_certificate():
    data = request.get_json()
    message = ca_server.revoke_certificate(data['host'], data['common_name'])
    return {'message': message}, 200

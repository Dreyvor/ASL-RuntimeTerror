function computeResponse() {
    let challenge = document.getElementById('challenge').value;
    const file = document.getElementById('file').files[0];
    checkFileExtension(document.getElementById('file'))
    document.getElementById('file').value = '';
    let reader = new FileReader();
    reader.onload = function (e) {
        let contents = e.target.result;
        const values = getPrivateKey(forge.pkcs12.pkcs12FromAsn1(forge.asn1.fromDer(arrayBufferToString(contents)),));
        const privateKey = values[0];
        const certificate = values[1];
        document.getElementById('certificate').value = encodeCertificate(certificate);
        const privateKeyPkcs8 = privateKeyToPkcs8(privateKey);
        importPrivateKey(privateKeyPkcs8, false).then(function (cryptoKey) {
            sign(cryptoKey, challenge.toString());
        });
    }
    reader.readAsArrayBuffer(file);
}

function checkFileExtension(input) {
    const extensions = [".p12"];
    if (input.type === "file") {
        let name = input.value;
        if (name.length > 0) {
            let valid = false;
            for (let i = 0; i < extensions.length; i++) {
                if (name.substr(name.length - extensions[i].length, extensions[i].length).toLowerCase() === extensions[i].toLowerCase()) {
                    valid = true;
                    break;
                }
            }
            if (!valid) {
                alert("Invalid file extension. Allowed are: " + extensions.join(", "));
                return false;
            }
        } else {
            alert("Please select your certificate...")
            return false;
        }
    }
    return true;
}

function encodeCertificate(certificate) {
    return forge.util.encode64(forge.asn1.toDer(forge.pki.certificateToAsn1(certificate)).getBytes());
}

function sign(privateKey, content) {
    let digestToSignBuf = stringToArrayBuffer(content);
    crypto.subtle.sign({name: "RSASSA-PKCS1-v1_5"}, privateKey, digestToSignBuf).then(function (signature) {
        document.getElementById('challenge').value = forge.util.encode64(arrayBufferToString(signature));
        form.submit()
    });
}

function importPrivateKey(privateKey, is_extractable) {
    return crypto.subtle.importKey('pkcs8', privateKey, {name: "RSASSA-PKCS1-v1_5", hash: {name: "SHA-256"}}, is_extractable, ["sign"]);
}

function privateKeyToPkcs8(privateKey) {
    return stringToArrayBuffer(forge.asn1.toDer(forge.pki.wrapRsaPrivateKey(forge.pki.privateKeyToAsn1(privateKey))).getBytes());
}

function stringToArrayBuffer(data) {
    let buffer = new ArrayBuffer(data.length);
    let array = new Uint8Array(buffer);
    for (let i = 0; i < data.length; i++) {
        array[i] = data.charCodeAt(i);
    }
    return buffer;
}

function getPrivateKey(pkcs12) {
    let privateKey = null;
    let cert = null;
    for (let i = 0; i < pkcs12.safeContents.length; i++) {
        let safeContents = pkcs12.safeContents[i];
        for (let j = 0; j < safeContents.safeBags.length; j++) {
            let safeBag = safeContents.safeBags[j];
            if (safeBag.type === forge.pki.oids.keyBag) {
                privateKey = safeBag.key;
            } else if (safeBag.type === forge.pki.oids.pkcs8ShroudedKeyBag) {
                privateKey = safeBag.key;
            } else if (safeBag.type === forge.pki.oids.certBag) {
                cert = safeBag.cert
            }
        }
    }
    return [privateKey, cert]
}

function arrayBufferToString(buffer) {
    let binary = '';
    let bytes = new Uint8Array(buffer);
    for (let i = 0; i < bytes.byteLength; i++) {
        binary += String.fromCharCode(bytes[i]);
    }
    return binary;
}

function hashPassword() {
    let password = document.getElementById('password');
    if (password.value !== "") {
        let sha1 = new jsSHA("SHA-1", "TEXT", {numRounds: 1});
        sha1.update(password.value);
        password.value = sha1.getHash("HEX")
    }
}
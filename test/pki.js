const fs = require('fs');
const { expect } = require("chai");
const { ethers } = require("hardhat");
const { PublicKeyInfo, CertificationRequest, AttributeTypeAndValue, setEngine, CryptoEngine, Certificate, Extension, BasicConstraints, AuthorityKeyIdentifier } = require('pkijs');
const { PrintableString, fromBER, Integer, OctetString } = require('asn1js');
const { generateKeyPairSync, createPublicKey, createPrivateKey, createHash, webcrypto, subtle } = require('crypto');
const { arrayBufferToString, toBase64 } = require('pvutils');

describe("PKI", function () {

    const passphrase = 'top secret';

    const index = {
        "subject": {
            "commonName": 0,
            "organization": 1,
            "locality": 2,
            "state": 3,
            "country": 4,
        },
        "issuer": {
            "commonName": 5,
            "organization": 6,
            "locality": 7,
            "state": 8,
            "country": 9,
        },
        "validity": {
            "notBefore": 10,
            "notAfter": 11,
        },
        "subjectAltName": {
            "dnsNames": 12,
            "ipAddresses": 13,
            "emailAddresses": 14,
            "uris": 15,
        },
        "publicKeyInfo": {
            "algorithm": 16,
            "keySize": 17,
            "publicKey": 18
        },
        "miscellaneous": {
            "version": 19,
            "serialNumber": 20,
            "signatureAlgorithm": 21,
        },
        "fingerprints": {
            "sha1": 22,
            "_sha256": 23,
        },
        "basicConstraints": {
            "isCA": 24,
            "pathLenConstraint": 25,
        },
        "extensions": {
            "subjectWalletAddress": 26,
            "issuerContractAddress": 27,
            "blockchainName": 28,
            "contractAddress": 29,
        },
        "subjectKeyIdentifier": 30,
        "authorityKeyIdentifier": 31,
        "signature": 32,
    }

    function formatPEM(pemString) {
        return pemString.match(/.{1,64}/g).join('\n');
    }

    function hexStringToArrayBuffer(hexString) {
        // remove the leading 0x
        hexString = hexString.replace(/^0x/, '');

        // Remove any spaces or non-hex characters from the string
        hexString = hexString.replace(/[^0-9a-fA-F]/g, '');

        // If the length of the string is odd, add a leading zero
        if (hexString.length % 2 !== 0) {
            hexString = '0' + hexString;
        }

        // Convert the hex string to an array of bytes
        const bytes = new Uint8Array(hexString.length / 2);
        for (let i = 0; i < hexString.length; i += 2) {
            bytes[i / 2] = parseInt(hexString.substr(i, 2), 16);
        }

        // Return the bytes as an ArrayBuffer
        return bytes;
    }

    function generateKeys() {
        const { publicKey, privateKey } = generateKeyPairSync('ec', {
            namedCurve: 'P-256',
            publicKeyEncoding: {
                type: 'spki',
                format: 'pem'
            },
            privateKeyEncoding: {
                type: 'pkcs8',
                format: 'pem',
                cipher: 'aes-256-cbc',
                passphrase: passphrase
            }
        });

        return { publicKey, privateKey };
    }

    async function generateCSR(cert, requesterPublicKey, requesterPrivateKey, password) {
        const csr = new CertificationRequest();

        csr.version = 0;
        csr.subject.typesAndValues.push(new AttributeTypeAndValue({
            type: "2.5.4.6", // Country name
            value: new PrintableString({ value: cert[index['subject']['country']] })
        }));

        csr.subject.typesAndValues.push(new AttributeTypeAndValue({
            type: '2.5.4.7', //localityName
            value: new PrintableString({ value: cert[index['subject']['locality']] })
        }));

        csr.subject.typesAndValues.push(new AttributeTypeAndValue({
            type: '2.5.4.8', //stateOrProvinceName
            value: new PrintableString({ value: cert[index['subject']['state']] })
        }));

        csr.subject.typesAndValues.push(new AttributeTypeAndValue({
            type: '2.5.4.10', //organizationName
            value: new PrintableString({ value: cert[index['subject']['organization']] })
        }));

        csr.subject.typesAndValues.push(new AttributeTypeAndValue({
            type: '2.5.4.3', //commonName
            value: new PrintableString({ value: cert[index['subject']['commonName']] })
        }));

        csr.attributes = [];

        // Set the public key in the CSR
        const berPublicKey = createPublicKey(requesterPublicKey).export({ type: 'spki', format: 'der' });
        const asn1 = fromBER(berPublicKey);
        const pubKey = new PublicKeyInfo({ schema: asn1.result });
        csr.subjectPublicKeyInfo = pubKey;

        // await csr.subjectPublicKeyInfo.importKey(publicKey);
        const berPrivateKey = createPrivateKey({ key: requesterPrivateKey, type: 'pkcs8', format: 'pem', passphrase: password }).export({
            format: 'der',
            type: 'pkcs8',
        });
        setEngine('OpenSSL', webcrypto, new CryptoEngine({
            name: 'OpenSSL',
            crypto: webcrypto,
            subtle: webcrypto.subtle
        }));

        const cryptoPrivateKey = await subtle.importKey('pkcs8', berPrivateKey, { name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign']);

        await csr.sign(cryptoPrivateKey, 'SHA-256');

        return `-----BEGIN CERTIFICATE REQUEST-----\n${formatPEM(
            toBase64(
                arrayBufferToString(
                    csr.toSchema().toBER(false)
                )
            )
        )}\n-----END CERTIFICATE REQUEST-----`;
    }

    async function issueCertificate(issuer, subject, issuerPrivateKey, password) {

        const certificate = new Certificate()
        certificate.version = 2;
        certificate.serialNumber = new Integer({ value: subject[index['miscellaneous']['serialNumber']] });

        certificate.subject.typesAndValues.push(new AttributeTypeAndValue({
            type: '2.5.4.3', //commonName
            value: new PrintableString({ value: subject[index['subject']['commonName']] })
        }));

        certificate.subject.typesAndValues.push(new AttributeTypeAndValue({
            type: "2.5.4.6", // Country name
            value: new PrintableString({ value: subject[index['subject']['country']] })
        }));

        certificate.subject.typesAndValues.push(new AttributeTypeAndValue({
            type: '2.5.4.7', //localityName
            value: new PrintableString({ value: subject[index['subject']['locality']] })
        }));

        certificate.subject.typesAndValues.push(new AttributeTypeAndValue({
            type: '2.5.4.8', //stateOrProvinceName
            value: new PrintableString({ value: subject[index['subject']['state']] })
        }));

        certificate.subject.typesAndValues.push(new AttributeTypeAndValue({
            type: '2.5.4.10', //organizationName
            value: new PrintableString({ value: subject[index['subject']['organization']] })
        }));


        certificate.issuer.typesAndValues.push(new AttributeTypeAndValue({
            type: '2.5.4.3', //commonName
            value: new PrintableString({ value: issuer[index['subject']['commonName']] })
        }));

        certificate.issuer.typesAndValues.push(new AttributeTypeAndValue({
            type: "2.5.4.6", // Country name
            value: new PrintableString({ value: issuer[index['subject']['country']] })
        }));

        certificate.issuer.typesAndValues.push(new AttributeTypeAndValue({
            type: '2.5.4.7', //localityName
            value: new PrintableString({ value: issuer[index['subject']['locality']] })
        }));

        certificate.issuer.typesAndValues.push(new AttributeTypeAndValue({
            type: '2.5.4.8', //stateOrProvinceName
            value: new PrintableString({ value: issuer[index['subject']['state']] })
        }));

        certificate.issuer.typesAndValues.push(new AttributeTypeAndValue({
            type: '2.5.4.10', //organizationName
            value: new PrintableString({ value: issuer[index['subject']['organization']] })
        }));

        // Set the public key
        const berPublicKey = createPublicKey(subject[index['publicKeyInfo']['publicKey']]).export({ type: 'spki', format: 'der' });
        const asn1 = fromBER(berPublicKey);
        const pubKey = new PublicKeyInfo({ schema: asn1.result });
        certificate.subjectPublicKeyInfo = pubKey;

        // Set the validity period (1 year)
        const notBefore = new Date();
        const notAfter = new Date(notBefore);
        notAfter.setFullYear(notBefore.getFullYear() + 1);
        certificate.notBefore.value = notBefore;
        certificate.notAfter.value = notAfter;

        const basicConstr = new BasicConstraints({
            cA: true,
            pathLenConstraint: 3
        });
        certificate.extensions = [];
        certificate.extensions.push(new Extension({
            extnID: "2.5.29.19",
            critical: false,
            extnValue: basicConstr.toSchema().toBER(false),
            parsedValue: basicConstr // Parsed value for well-known extensions
        }));

        const subjectKeyIdentifier = createHash('sha1').update(subject[index['publicKeyInfo']['publicKey']]).digest();
        certificate.extensions.push(new Extension({
            extnID: "2.5.29.14",
            extnValue: new OctetString({ valueHex: subjectKeyIdentifier }).toBER(false),
        }));

        const authorityKeyIdentifier = createHash('sha1').update(issuer[index['publicKeyInfo']['publicKey']]).digest();

        if (authorityKeyIdentifier.toString() !== subjectKeyIdentifier.toString()) {
            certificate.extensions.push(new Extension({
                extnID: "2.5.29.35",
                extnValue: new AuthorityKeyIdentifier({
                    keyIdentifier: new OctetString({ valueHex: authorityKeyIdentifier }),
                }).toSchema().toBER(false),
            }));
        }

        certificate.extensions.push(new Extension({
            extnID: "2.5.29.5000", // X509v3 Subject Wallet Address, the OID is not registered
            extnValue: new OctetString({ valueHex: hexStringToArrayBuffer(subject[index['extensions']['subjectWalletAddress']]) }).toBER(false),
        }));

        certificate.extensions.push(new Extension({
            extnID: "2.5.29.5001", // X509v3 Issuer Contract identifier, the OID is not registered
            extnValue: new OctetString({ valueHex: hexStringToArrayBuffer(issuer[index['extensions']['contractAddress']]) }).toBER(false),
        }));

        certificate.extensions.push(new Extension({
            extnID: "2.5.29.5002", // X509v3 Blockchain name, the OID is not registered
            extnValue: new PrintableString({ value: issuer[index['extensions']['blockchainName']] }).toBER(false),
        }));

        if (subject[index['basicConstraints']['isCA']] === 'true' && authorityKeyIdentifier.toString() !== subjectKeyIdentifier.toString()) {
            certificate.extensions.push(new Extension({
                extnID: "2.5.29.5003", // X509v3 Contract identifier, the OID is not registered
                extnValue: new OctetString({ valueHex: hexStringToArrayBuffer(subject[index['extensions']['contractAddress']]) }).toBER(false),
            }));
        }
        // Sign the certificate with the private key
        const berPrivateKey = createPrivateKey({ key: issuerPrivateKey, type: 'pkcs8', format: 'pem', passphrase: password }).export({
            format: 'der',
            type: 'pkcs8',
        });
        setEngine('OpenSSL', webcrypto, new CryptoEngine({
            name: 'OpenSSL',
            crypto: webcrypto,
            subtle: webcrypto.subtle
        }));

        const cryptoPrivateKey = await subtle.importKey('pkcs8', berPrivateKey, { name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign']);

        await certificate.sign(cryptoPrivateKey, 'SHA-256');

        const pem = `-----BEGIN CERTIFICATE-----\n${formatPEM(
            toBase64(
                arrayBufferToString(
                    certificate.toSchema().toBER(false)
                )
            )
        )}\n-----END CERTIFICATE-----`;
        const signature = certificate.signatureValue.toString(16);
        const subjectKey = Buffer.from(subjectKeyIdentifier).toString('hex');

        return { pem, signature, subjectKey };
    }

    var { publicKey, privateKey } = generateKeys();
    const rootCaPublicKey = publicKey;
    const rootCaPrivateKey = privateKey;
    const rootCaCertificate = ["Blockchain Root CA", "Root CA", "TRZ", "TN", "IN", "Blockchain Root CA", "Root CA", "TRZ", "TN", "IN", "1681161711", "1781161711", "", "", "", "", "Elliptic Curve", "256", "", "3", "0", "", "", "", "true", "0", "", "", "Sepolia", "", "", "", ""];
    rootCaCertificate[index['publicKeyInfo']['publicKey']] = publicKey;
    fs.writeFileSync('rootCaPrivateKey.pem', rootCaPrivateKey);
    fs.writeFileSync('rootCaPublicKey.pem', rootCaPublicKey);
    fs.writeFileSync('UnlockedRootCaPrivateKey.pem', createPrivateKey({ key: rootCaPrivateKey, type: 'pkcs8', format: 'pem', passphrase: passphrase }).export({
        format: 'pem',
        type: 'pkcs8',
    }));
    // console.log('rootCaCertificate: ', rootCaCertificate);
    // console.log('Root Private Key: ', createPrivateKey({ key: rootCaPrivateKey, type: 'pkcs8', format: 'pem', passphrase: passphrase }).export({
    //     format: 'pem',
    //     type: 'pkcs8',
    // }));

    var { publicKey, privateKey } = generateKeys();
    const subCaPublicKey = publicKey;
    const subCaPrivateKey = privateKey;
    const subCaCertificate = ["Blockchain Sub CA", "Sub CA", "TRZ", "TN", "IN", "", "", "", "", "", "1681161711", "1781161711", "", "", "", "", "Elliptic Curve", "256", "", "3", "", "", "", "", "true", "0", "", "", "Sepolia", "", "", "", ""];
    subCaCertificate[index['publicKeyInfo']['publicKey']] = publicKey;
    fs.writeFileSync('subCaPrivateKey.pem', subCaPrivateKey);
    fs.writeFileSync('subCaPublicKey.pem', subCaPublicKey);
    fs.writeFileSync('UnlockedSubCaPrivateKey.pem', createPrivateKey({ key: subCaPrivateKey, type: 'pkcs8', format: 'pem', passphrase: passphrase }).export({
        format: 'pem',
        type: 'pkcs8',
    }));
    // console.log('subCaCertificate: ', subCaCertificate);
    // console.log('SubCA Private Key: ', createPrivateKey({ key: subCaPrivateKey, type: 'pkcs8', format: 'pem', passphrase: passphrase }).export({
    //     format: 'pem',
    //     type: 'pkcs8',
    // }));

    var { publicKey, privateKey } = generateKeys();
    const userPublicKey = publicKey;
    const userPrivateKey = privateKey;
    const userCertificate = ["Blockchain User 1", "User", "TRZ", "TN", "IN", "", "", "", "", "", "1681161711", "1781161711", "", "", "", "", "Elliptic Curve", "256", "", "3", "", "", "", "", "false", "0", "", "", "Sepolia", "", "", "", ""];
    userCertificate[index['publicKeyInfo']['publicKey']] = publicKey;
    fs.writeFileSync('userPrivateKey.pem', userPrivateKey);
    fs.writeFileSync('userPublicKey.pem', userPublicKey);
    fs.writeFileSync('UnlockedUserPrivateKey.pem', createPrivateKey({ key: userPrivateKey, type: 'pkcs8', format: 'pem', passphrase: passphrase }).export({
        format: 'pem',
        type: 'pkcs8',
    }));
    // console.log('userCaCertificate: ', userCertificate);
    // console.log('User Private Key: ', createPrivateKey({ key: userPrivateKey, type: 'pkcs8', format: 'pem', passphrase: passphrase }).export({
    //     format: 'pem',
    //     type: 'pkcs8',
    // }));

    var { publicKey, privateKey } = generateKeys();
    const rejectUserPublicKey = publicKey;
    const rejectUserPrivateKey = privateKey;
    const rejectUserCertificate = ["Blockchain User 2", "User", "TRZ", "TN", "IN", "", "", "", "", "", "1681161711", "1781161711", "", "", "", "", "Elliptic Curve", "256", "", "3", "", "", "", "", "false", "0", "", "", "Sepolia", "", "", "", ""];
    rejectUserCertificate[index['publicKeyInfo']['publicKey']] = publicKey;
    fs.writeFileSync('rejectUserPrivateKey.pem', rejectUserPrivateKey);
    fs.writeFileSync('rejectUserPublicKey.pem', rejectUserPublicKey);
    fs.writeFileSync('UnlockedRejectUserPrivateKey.pem', createPrivateKey({ key: rejectUserPrivateKey, type: 'pkcs8', format: 'pem', passphrase: passphrase }).export({
        format: 'pem',
        type: 'pkcs8',
    }));
    // console.log('rejectUserCaCertificate: ', rejectUserCertificate);
    // console.log('RejectUser Private Key: ', createPrivateKey({ key: rejectUserPrivateKey, type: 'pkcs8', format: 'pem', passphrase: passphrase }).export({
    //     format: 'pem',
    //     type: 'pkcs8',
    // }));

    // A single test is being used to preserve state instead of having different tests which resets the state of the contract
    it("Everything", async function () {
        // Deploy Root CA
        const PKI = await ethers.getContractFactory("PKI");
        const [rootCA, subCA, user, rejectUser] = await ethers.getSigners();
        const rootContract = await PKI.deploy();
        await rootContract.deployed();
        expect(await rootContract.owner()).to.equal(rootCA.address);


        // fill root ca certificate values
        rootCaCertificate[index["extensions"]["contractAddress"]] = rootContract.address;
        rootCaCertificate[index["extensions"]["subjectWalletAddress"]] = rootCA.address;

        // generate a self signed certificate
        var { pem, signature, subjectKey } = await issueCertificate(rootCaCertificate, rootCaCertificate, rootCaPrivateKey, passphrase);
        const rootCaCertificateCrt = pem;
        fs.writeFileSync('rootCaCertificate.crt', rootCaCertificateCrt);

        rootCaCertificate[index['subjectKeyIdentifier']] = subjectKey;
        rootCaCertificate[index['signature']] = signature;

        // assign CaCertificate in the Root CA smartcontract
        await rootContract.populateCaCertificate(rootCaCertificate, pem);
        expect(rootCaCertificate).to.deep.equal(await rootContract.getCaCertificate());

        // Should request CA Certificate
        const subCaRequestTx = await rootContract.connect(subCA).requestCertificate(subCaCertificate);
        const subCaReceipt = await subCaRequestTx.wait();
        const SubCaCertificateRequestedEvent = subCaReceipt.events.find(event => event.event === "CertificateRequested");
        const subCaSerialNumber = SubCaCertificateRequestedEvent.args.serialNumber;
        expect(subCaSerialNumber).to.equal(1);
        expect(await rootContract.getCertificateStatus(subCaSerialNumber)).to.equal(0);

        // sub ca generating a csr
        const subCSR = await generateCSR(subCaCertificate, subCaPublicKey, subCaPrivateKey, passphrase);
        fs.writeFileSync('subCaCSR.csr', subCSR);

        // Deploy Sub CA
        const subCaContract = await PKI.connect(rootCA).deploy();
        expect(await subCaContract.owner()).to.equal(rootCA.address);

        // root issuing a certificate
        const subCaCertificateFromContract = Object.assign([], await rootContract.getPendingCertificate()); // the returned array is not extensible
        subCaCertificateFromContract[index['extensions']['contractAddress']] = subCaContract.address;
        var { pem, signature, subjectKey } = await issueCertificate(rootCaCertificate, subCaCertificateFromContract, rootCaPrivateKey, passphrase);
        const subCaCertificateCrt = pem;
        fs.writeFileSync('subCaCertificate.crt', subCaCertificateCrt);

        // Should Issue CA Certificate
        await rootContract.issuePendingCertificate(signature, subCaContract.address, subjectKey, pem);
        expect(await rootContract.getCertificateStatus(subCaSerialNumber)).to.equal(1);

        // assign CaCertificate in the Sub CA smartcontract
        const issuedSubCaCertificateFromContract = await rootContract["getCertificate(uint256)"](1);
        await subCaContract.populateCaCertificate(issuedSubCaCertificateFromContract, pem);
        expect(issuedSubCaCertificateFromContract).to.deep.equal(await subCaContract.getCaCertificate());

        // Transfer owner
        await subCaContract.connect(rootCA).transferOwnership(subCA.address);
        expect(await subCaContract.owner()).to.equal(subCA.address);

        // Should request and issue user Certificate
        const userRequestTx = await subCaContract.connect(user).requestCertificate(userCertificate);
        const userReceipt = await userRequestTx.wait();
        const userCertificateRequestedEvent = userReceipt.events.find(event => event.event === "CertificateRequested");
        const userSerialNumber = userCertificateRequestedEvent.args.serialNumber;
        expect(userSerialNumber).to.equal(1);
        expect(await subCaContract.getCertificateStatus(userSerialNumber)).to.equal(0);

        // user generating a csr
        const userCSR = await generateCSR(userCertificate, userPublicKey, userPrivateKey, passphrase);
        fs.writeFileSync('userCSR.csr', userCSR);

        // sub CA issuing a certificate
        const userCertificateFromContract = await subCaContract.connect(subCA).getPendingCertificate();
        var { pem, signature, subjectKey } = await issueCertificate(issuedSubCaCertificateFromContract, userCertificateFromContract, subCaPrivateKey, passphrase);
        const userCertificateCrt = pem;
        fs.writeFileSync('userCertificate.crt', userCertificateCrt);

        await subCaContract.connect(subCA).issuePendingCertificate(signature, "", subjectKey, pem);
        expect(await subCaContract.getCertificateStatus(userSerialNumber)).to.equal(1);

        // Revoke user
        await subCaContract.connect(subCA).revokeCertificate(userSerialNumber);
        expect(await subCaContract.getCertificateStatus(userSerialNumber)).to.equal(2);

        // rejectPendingCertificate
        const rejectUserRequestTx = await subCaContract.connect(rejectUser).requestCertificate(rejectUserCertificate);
        const rejectUserReceipt = await rejectUserRequestTx.wait();
        const rejectUserCertificateRequestedEvent = rejectUserReceipt.events.find(event => event.event === "CertificateRequested");
        const rejectUserSerialNumber = rejectUserCertificateRequestedEvent.args.serialNumber;
        expect(rejectUserSerialNumber).to.equal(2);
        await subCaContract.connect(subCA).rejectPendingCertificate();
        expect(await subCaContract.getCertificateStatus(rejectUserSerialNumber)).to.equal(3);

        // Other function
        // getCertificate Name
        expect(issuedSubCaCertificateFromContract).to.deep.equal(await rootContract["getCertificate(string)"]("Blockchain Sub CA"));
    });
});

const { expect } = require("chai");
const { ethers } = require("hardhat");
const { PublicKeyInfo, CertificationRequest, AttributeTypeAndValue, setEngine, CryptoEngine, Certificate, AlgorithmIdentifier, Extension, BasicConstraints } = require('pkijs');
const { PrintableString, Utf8String, fromBER, Integer, Null, BitString } = require('asn1js');
const { generateKeyPairSync, createPublicKey, createPrivateKey, createHash, webcrypto, subtle, sign } = require('crypto');
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
            "subjectAddress": 26,
            "issuerAddress": 27,
            "blockchainName": 28,
            "caAddress": 29,
        },
        "subjectKeyIdentifier": 30,
        "authorityKeyIdentifier": 31,
        "signature": 32,
    }

    function formatPEM(pemString) {
        return pemString.replace(/(.{64})/g, '$1\n')
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

        const publicKeyDer = createPublicKey(publicKey)
            .export({
                format: 'der',
                type: 'spki'
            });

        const hexPublicKey = publicKeyDer.toString('hex');
        const sha1 = createHash('sha1').update(publicKeyDer).digest('hex');
        const subjectKeyIdentifier = sha1;
        return { hexPublicKey, publicKey, privateKey, subjectKeyIdentifier };
    }

    async function generateCSR(cert, publicKey, privateKey) {
        const csr = new CertificationRequest();

        csr.version = 0;
        csr.subject.typesAndValues.push(new AttributeTypeAndValue({
            type: "2.5.4.6", // Country name
            value: new PrintableString({ value: cert[index['subject']['country']] })
        }));

        csr.subject.typesAndValues.push(new AttributeTypeAndValue({
            type: '2.5.4.7', //localityName
            value: new Utf8String({ value: cert[index['subject']['locality']] })
        }));

        csr.subject.typesAndValues.push(new AttributeTypeAndValue({
            type: '2.5.4.8', //stateOrProvinceName
            value: new Utf8String({ value: cert[index['subject']['state']] })
        }));

        csr.subject.typesAndValues.push(new AttributeTypeAndValue({
            type: '2.5.4.10', //organizationName
            value: new Utf8String({ value: cert[index['subject']['organization']] })
        }));

        csr.subject.typesAndValues.push(new AttributeTypeAndValue({
            type: '2.5.4.3', //commonName
            value: new Utf8String({ value: cert[index['subject']['commonName']] })
        }));

        csr.attributes = [];

        // Set the public key in the CSR
        const berPublicKey = createPublicKey(publicKey).export({ type: 'spki', format: 'der' });
        const asn1 = fromBER(berPublicKey);
        const pubKey = new PublicKeyInfo({ schema: asn1.result });
        csr.subjectPublicKeyInfo = pubKey;

        // await csr.subjectPublicKeyInfo.importKey(publicKey);
        const berPrivateKey = createPrivateKey({ key: privateKey, type: 'pkcs8', format: 'pem', passphrase: passphrase }).export({
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

    var { hexPublicKey, publicKey, privateKey, subjectKeyIdentifier } = generateKeys();
    const rootCaPublicKey = publicKey;
    const rootCaPrivateKey = privateKey;
    const rootCaCertificate = ["Blockchain Root CA", "Root CA", "TRZ", "TN", "IN", "Blockchain Root CA", "Root CA", "TRZ", "TN", "IN", "1681161711", "1781161711", "", "", "", "", "", "", "", "3", "0", "", "sha1", "sha256", "true", "0", "", "", "Sepolia", "", "SubjectKeyIdentifier", "AuthorityKeyIdentifier", "Signature"];
    rootCaCertificate[index['publicKeyInfo']['publicKey']] = hexPublicKey;
    rootCaCertificate[index['publicKeyInfo']['keySize']] = '256';
    rootCaCertificate[index['publicKeyInfo']['algorithm']] = 'Elliptic Curve';
    rootCaCertificate[index['subjectKeyIdentifier']] = subjectKeyIdentifier;
    console.log('rootCaCertificate: ', rootCaCertificate);
    console.log('Root Private Key: ', createPrivateKey({ key: rootCaPrivateKey, type: 'pkcs8', format: 'pem', passphrase: passphrase }).export({
        format: 'pem',
        type: 'pkcs8',
    }));

    var { hexPublicKey, publicKey, privateKey, subjectKeyIdentifier } = generateKeys();
    const subCaPublicKey = publicKey;
    const subCaPrivateKey = privateKey;
    const subCaCertificate = ["Blockchain Sub CA", "Sub CA", "TRZ", "TN", "IN", "", "", "", "", "", "1681161711", "1781161711", "", "", "", "", "", "", "", "3", "", "", "sha1", "sha256", "true", "0", "", "", "Sepolia", "", "SubjectKeyIdentifier", "AuthorityKeyIdentifier", "Signature"];
    subCaCertificate[index['publicKeyInfo']['publicKey']] = hexPublicKey;
    subCaCertificate[index['publicKeyInfo']['keySize']] = '256';
    subCaCertificate[index['publicKeyInfo']['algorithm']] = 'Elliptic Curve';
    subCaCertificate[index['subjectKeyIdentifier']] = subjectKeyIdentifier;
    console.log('subCaCertificate: ', subCaCertificate);
    console.log('SubCA Private Key: ', createPrivateKey({ key: subCaPrivateKey, type: 'pkcs8', format: 'pem', passphrase: passphrase }).export({
        format: 'pem',
        type: 'pkcs8',
    }));

    var { hexPublicKey, publicKey, privateKey, subjectKeyIdentifier } = generateKeys();
    const userPublicKey = publicKey;
    const userPrivateKey = privateKey;
    const userCertificate = ["Blockchain User 1", "User", "TRZ", "TN", "IN", "", "", "", "", "", "1681161711", "1781161711", "", "", "", "", "", "", "", "3", "", "", "sha1", "sha256", "false", "0", "", "", "Sepolia", "", "SubjectKeyIdentifier", "AuthorityKeyIdentifier", "Signature"];
    userCertificate[index['publicKeyInfo']['publicKey']] = hexPublicKey;
    userCertificate[index['publicKeyInfo']['keySize']] = '256';
    userCertificate[index['publicKeyInfo']['algorithm']] = 'Elliptic Curve';
    userCertificate[index['subjectKeyIdentifier']] = subjectKeyIdentifier;
    console.log('userCaCertificate: ', userCertificate);
    console.log('User Private Key: ', createPrivateKey({ key: userPrivateKey, type: 'pkcs8', format: 'pem', passphrase: passphrase }).export({
        format: 'pem',
        type: 'pkcs8',
    }));

    var { hexPublicKey, publicKey, privateKey, subjectKeyIdentifier } = generateKeys();
    const rejectUserPublicKey = publicKey;
    const rejectUserPrivateKey = privateKey;
    const rejectUserCertificate = ["Blockchain User 2", "User", "TRZ", "TN", "IN", "", "", "", "", "", "1681161711", "1781161711", "", "", "", "", "", "", "", "3", "", "", "sha1", "sha256", "false", "0", "", "", "Sepolia", "", "SubjectKeyIdentifier", "AuthorityKeyIdentifier", "Signature"];
    rejectUserCertificate[index['publicKeyInfo']['publicKey']] = hexPublicKey;
    rejectUserCertificate[index['publicKeyInfo']['keySize']] = '256';
    rejectUserCertificate[index['publicKeyInfo']['algorithm']] = 'Elliptic Curve';
    rejectUserCertificate[index['subjectKeyIdentifier']] = subjectKeyIdentifier;
    console.log('rejectUserCaCertificate: ', rejectUserCertificate);
    console.log('RejectUser Private Key: ', createPrivateKey({ key: rejectUserPrivateKey, type: 'pkcs8', format: 'pem', passphrase: passphrase }).export({
        format: 'pem',
        type: 'pkcs8',
    }));

    // A single test is being used to preserve state instead of having different tests which resets the state of the contract
    it("Everything", async function () {
        // Deploy Root CA
        const PKI = await ethers.getContractFactory("PKI");
        const [rootCA, subCA, user, rejectUser] = await ethers.getSigners();
        const rootContract = await PKI.deploy();
        await rootContract.deployed();
        expect(await rootContract.owner()).to.equal(rootCA.address);





        // generate a self signed certificate
        const issuedRootCaCertificate = new Certificate()
        issuedRootCaCertificate.version = 2;
        issuedRootCaCertificate.serialNumber = new Integer({ value: 0 });

        issuedRootCaCertificate.subject.typesAndValues.push(new AttributeTypeAndValue({
            type: '2.5.4.3', //commonName
            value: new Utf8String({ value: rootCaCertificate[index['subject']['commonName']] })
        }));

        issuedRootCaCertificate.subject.typesAndValues.push(new AttributeTypeAndValue({
            type: "2.5.4.6", // Country name
            value: new PrintableString({ value: rootCaCertificate[index['subject']['country']] })
        }));

        issuedRootCaCertificate.subject.typesAndValues.push(new AttributeTypeAndValue({
            type: '2.5.4.7', //localityName
            value: new Utf8String({ value: rootCaCertificate[index['subject']['locality']] })
        }));

        issuedRootCaCertificate.subject.typesAndValues.push(new AttributeTypeAndValue({
            type: '2.5.4.8', //stateOrProvinceName
            value: new Utf8String({ value: rootCaCertificate[index['subject']['state']] })
        }));

        issuedRootCaCertificate.subject.typesAndValues.push(new AttributeTypeAndValue({
            type: '2.5.4.10', //organizationName
            value: new Utf8String({ value: rootCaCertificate[index['subject']['organization']] })
        }));


        issuedRootCaCertificate.issuer.typesAndValues.push(new AttributeTypeAndValue({
            type: '2.5.4.3', //commonName
            value: new Utf8String({ value: rootCaCertificate[index['subject']['commonName']] })
        }));

        issuedRootCaCertificate.issuer.typesAndValues.push(new AttributeTypeAndValue({
            type: "2.5.4.6", // Country name
            value: new PrintableString({ value: rootCaCertificate[index['subject']['country']] })
        }));

        issuedRootCaCertificate.issuer.typesAndValues.push(new AttributeTypeAndValue({
            type: '2.5.4.7', //localityName
            value: new Utf8String({ value: rootCaCertificate[index['subject']['locality']] })
        }));

        issuedRootCaCertificate.issuer.typesAndValues.push(new AttributeTypeAndValue({
            type: '2.5.4.8', //stateOrProvinceName
            value: new Utf8String({ value: rootCaCertificate[index['subject']['state']] })
        }));

        issuedRootCaCertificate.issuer.typesAndValues.push(new AttributeTypeAndValue({
            type: '2.5.4.10', //organizationName
            value: new Utf8String({ value: rootCaCertificate[index['subject']['organization']] })
        }));

        // Set the public key
        const berRootCaPublicKey = createPublicKey(rootCaPublicKey).export({ type: 'spki', format: 'der' });
        const asn1 = fromBER(berRootCaPublicKey);
        const pubKey = new PublicKeyInfo({ schema: asn1.result });
        issuedRootCaCertificate.subjectPublicKeyInfo = pubKey;

        // Set the validity period (1 year)
        const notBefore = new Date();
        const notAfter = new Date(notBefore);
        notAfter.setFullYear(notBefore.getFullYear() + 1);
        issuedRootCaCertificate.notBefore.value = notBefore;
        issuedRootCaCertificate.notAfter.value = notAfter;

        const basicConstr = new BasicConstraints({
            cA: true,
            pathLenConstraint: 3
        });
        issuedRootCaCertificate.extensions = [];
        issuedRootCaCertificate.extensions.push(new Extension({
            extnID: "2.5.29.19",
            critical: false,
            extnValue: basicConstr.toSchema().toBER(false),
            parsedValue: basicConstr // Parsed value for well-known extensions
        }));

        // Sign the certificate with the private key
        const pemRootCaPrivateKey = createPrivateKey({ key: rootCaPrivateKey, type: 'pkcs8', format: 'pem', passphrase: passphrase }).export({
            format: 'pem',
            type: 'pkcs8',
        });

        const signature = sign('sha256', Buffer.from(issuedRootCaCertificate.toSchema(true).toBER()), pemRootCaPrivateKey);
        issuedRootCaCertificate.signature = new AlgorithmIdentifier({
            algorithm: '1.2.840.10045.4.3.2', // ecdsa-with-SHA256
            parameters: new Null()
        });
        issuedRootCaCertificate.signatureValue = new BitString({ valueHex: signature });

        // // Encode the certificate as PEM
        const issuedRootCaCertificatePEM = issuedRootCaCertificate.toSchema(true).toBER(false);
        // const issuedRootCaCertificatePEMFormatted = pemFromBin(issuedRootCaCertificatePEM, 'CERTIFICATE');





        // assign CaCertificate in the Root CA smartcontract
        rootCaCertificate[index["extensions"]["caAddress"]] = rootContract.address;
        rootCaCertificate[index["extensions"]["issuerAddress"]] = rootCA.address;
        rootCaCertificate[index["extensions"]["subjectAddress"]] = rootCA.address;
        await rootContract.populateCaCertificate(rootCaCertificate);
        expect(rootCaCertificate).to.deep.equal(await rootContract.getCaCertificate());

        // Should request CA Certificate
        const subCaRequestTx = await rootContract.connect(subCA).requestCertificate(subCaCertificate);
        const subCaReceipt = await subCaRequestTx.wait();
        const SubCaCertificateRequestedEvent = subCaReceipt.events.find(event => event.event === "CertificateRequested");
        const subCaSerialNumber = SubCaCertificateRequestedEvent.args.serialNumber;
        expect(subCaSerialNumber).to.equal(1);
        expect(await rootContract.getCertificateStatus(subCaSerialNumber)).to.equal(0);

        // sub ca generating a csr
        const subCSR = await generateCSR(subCaCertificate, subCaPublicKey, subCaPrivateKey);

        // Deploy Sub CA
        const subCaContract = await PKI.connect(rootCA).deploy();
        expect(await subCaContract.owner()).to.equal(rootCA.address);

        // Should Issue CA Certificate
        await rootContract.issuePendingCertificate("toBeFilled", subCaContract.address);
        expect(await rootContract.getCertificateStatus(subCaSerialNumber)).to.equal(1);

        // assign CaCertificate in the Sub CA smartcontract
        const issuedSubCaCertificateFromContract = await rootContract["getCertificate(uint256)"](1);
        await subCaContract.populateCaCertificate(issuedSubCaCertificateFromContract);
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
        await subCaContract.connect(subCA).issuePendingCertificate("toBeFilled", "");
        expect(await subCaContract.getCertificateStatus(userSerialNumber)).to.equal(1);

        // Revoke user
        await subCaContract.connect(subCA).revokeCertificate(userSerialNumber);
        expect(await subCaContract.getCertificateStatus(userSerialNumber)).to.equal(2);

        // Other function
        // getCertificate Name
        expect(issuedSubCaCertificateFromContract).to.deep.equal(await rootContract["getCertificate(string)"]("Blockchain Sub CA"));

        // rejectPendingCertificate
        // Should request and issue user Certificate
        const rejectUserRequestTx = await subCaContract.connect(rejectUser).requestCertificate(rejectUserCertificate);
        const rejectUserReceipt = await rejectUserRequestTx.wait();
        const rejectUserCertificateRequestedEvent = rejectUserReceipt.events.find(event => event.event === "CertificateRequested");
        const rejectUserSerialNumber = rejectUserCertificateRequestedEvent.args.serialNumber;
        expect(rejectUserSerialNumber).to.equal(2);
        await subCaContract.connect(subCA).rejectPendingCertificate();
        expect(await subCaContract.getCertificateStatus(rejectUserSerialNumber)).to.equal(3);
    });
});

const fs = require('fs');
const { expect } = require("chai");
const { ethers } = require("hardhat");
const { PublicKeyInfo, CertificationRequest, AttributeTypeAndValue, setEngine, CryptoEngine, Certificate, Extension, BasicConstraints, AuthorityKeyIdentifier } = require('pkijs');
const { PrintableString, fromBER, Integer, OctetString } = require('asn1js');
const { generateKeyPairSync, createPublicKey, createPrivateKey, createHash, webcrypto, subtle } = require('crypto');
const { arrayBufferToString, toBase64, stringToArrayBuffer, fromBase64 } = require('pvutils');

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

    function generateKeys(password) {
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
                passphrase: password
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

        const certificate = new Certificate();
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
            subtle: subtle
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

    async function issueCertificateFromCSR(issuer, subjectCSR, issuerPrivateKey, password, subjectWalletAddress, contractAddress, serialNumber) {
        const berSubjectCSR = subjectCSR.replace(/-----BEGIN CERTIFICATE REQUEST-----/, '').replace(/-----END CERTIFICATE REQUEST-----/, '').replace(/\n/g, '');
        const derSubjectCSR = stringToArrayBuffer(fromBase64(berSubjectCSR));
        const asn1 = fromBER(derSubjectCSR);
        const cert = new CertificationRequest({ schema: asn1.result });
        const subjectCert = new Array(33);
        subjectCert[index['subject']['commonName']] = cert.subject.typesAndValues.find(typeAndValue => typeAndValue.type === '2.5.4.3').value.valueBlock.value;
        subjectCert[index['subject']['country']] = cert.subject.typesAndValues.find(typeAndValue => typeAndValue.type === '2.5.4.6').value.valueBlock.value;
        subjectCert[index['subject']['locality']] = cert.subject.typesAndValues.find(typeAndValue => typeAndValue.type === '2.5.4.7').value.valueBlock.value;
        subjectCert[index['subject']['state']] = cert.subject.typesAndValues.find(typeAndValue => typeAndValue.type === '2.5.4.8').value.valueBlock.value;
        subjectCert[index['subject']['organization']] = cert.subject.typesAndValues.find(typeAndValue => typeAndValue.type === '2.5.4.10').value.valueBlock.value;
        subjectCert[index['publicKeyInfo']['publicKey']] = `-----BEGIN PUBLIC KEY-----\n${formatPEM(
            toBase64(
                arrayBufferToString(
                    cert.subjectPublicKeyInfo.toSchema().toBER(false)
                )
            )
        )}\n-----END PUBLIC KEY-----`;
        subjectCert[index['miscellaneous']['serialNumber']] = serialNumber;
        subjectCert[index['extensions']['subjectWalletAddress']] = subjectWalletAddress;
        subjectCert[index['extensions']['contractAddress']] = contractAddress;
        return await issueCertificate(issuer, subjectCert, issuerPrivateKey, password);
    }

    const rootCaPublicKey = fs.readFileSync('reuseKeys/rootCaPublicKey.pem').toString();
    const rootCaPrivateKey = fs.readFileSync('reuseKeys/rootCaPrivateKey.pem').toString();
    const rootCaCertificate = ["Blockchain Root CA", "Root CA", "TRZ", "TN", "IN", "Blockchain Root CA", "Root CA", "TRZ", "TN", "IN", "1681161711", "1781161711", "", "", "", "", "Elliptic Curve", "256", "", "3", "0", "", "", "", "true", "0", "", "", "Sepolia", "", "", "", ""];
    rootCaCertificate[index['publicKeyInfo']['publicKey']] = rootCaPublicKey;

    const subCaPublicKey = fs.readFileSync('reuseKeys/subCaPublicKey.pem').toString();
    const subCaPrivateKey = fs.readFileSync('reuseKeys/subCaPrivateKey.pem').toString();
    const subCaCertificate = ["Blockchain Sub CA", "Sub CA", "TRZ", "TN", "IN", "", "", "", "", "", "1681161711", "1781161711", "", "", "", "", "Elliptic Curve", "256", "", "3", "", "", "", "", "true", "0", "", "", "Sepolia", "", "", "", ""];
    subCaCertificate[index['publicKeyInfo']['publicKey']] = subCaPublicKey;

    const userPublicKey = fs.readFileSync('reuseKeys/userPublicKey.pem').toString();
    const userPrivateKey = fs.readFileSync('reuseKeys/userPrivateKey.pem').toString();
    const userCertificate = ["Blockchain User 1", "User", "TRZ", "TN", "IN", "", "", "", "", "", "1681161711", "1781161711", "", "", "", "", "Elliptic Curve", "256", "", "3", "", "", "", "", "false", "0", "", "", "Sepolia", "", "", "", ""];
    userCertificate[index['publicKeyInfo']['publicKey']] = userPublicKey;

    const rejectUserPublicKey = fs.readFileSync('reuseKeys/rejectUserPublicKey.pem').toString();
    const rejectUserPrivateKey = fs.readFileSync('reuseKeys/rejectUserPrivateKey.pem').toString();
    const rejectUserCertificate = ["Blockchain User 2", "User", "TRZ", "TN", "IN", "", "", "", "", "", "1681161711", "1781161711", "", "", "", "", "Elliptic Curve", "256", "", "3", "", "", "", "", "false", "0", "", "", "Sepolia", "", "", "", ""];
    rejectUserCertificate[index['publicKeyInfo']['publicKey']] = rejectUserPublicKey;

    // A single test is being used to preserve state instead of having different tests which resets the state of the contract
    it("PKI Contract", async function () {
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
        expect(await rootContract["getCertificateStatus(uint256)"](subCaSerialNumber)).to.equal(0);

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
        expect(await rootContract["getCertificateStatus(uint256)"](subCaSerialNumber)).to.equal(1);

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
        expect(await subCaContract["getCertificateStatus(uint256)"](userSerialNumber)).to.equal(0);

        // sub CA issuing a certificate
        const userCertificateFromContract = await subCaContract.connect(subCA).getPendingCertificate();
        var { pem, signature, subjectKey } = await issueCertificate(issuedSubCaCertificateFromContract, userCertificateFromContract, subCaPrivateKey, passphrase);
        const userCertificateCrt = pem;
        fs.writeFileSync('userCertificate.crt', userCertificateCrt);

        await subCaContract.connect(subCA).issuePendingCertificate(signature, "", subjectKey, pem);
        expect(await subCaContract["getCertificateStatus(uint256)"](userSerialNumber)).to.equal(1);

        // Revoke user
        await subCaContract.connect(subCA).revokeCertificate(userSerialNumber);
        expect(await subCaContract["getCertificateStatus(uint256)"](userSerialNumber)).to.equal(2);

        // rejectPendingCertificate
        const rejectUserRequestTx = await subCaContract.connect(rejectUser).requestCertificate(rejectUserCertificate);
        const rejectUserReceipt = await rejectUserRequestTx.wait();
        const rejectUserCertificateRequestedEvent = rejectUserReceipt.events.find(event => event.event === "CertificateRequested");
        const rejectUserSerialNumber = rejectUserCertificateRequestedEvent.args.serialNumber;
        expect(rejectUserSerialNumber).to.equal(2);
        await subCaContract.connect(subCA).rejectPendingCertificate();
        expect(await subCaContract["getCertificateStatus(uint256)"](rejectUserSerialNumber)).to.equal(3);

        // Other function
        // getCertificate Name
        expect(issuedSubCaCertificateFromContract).to.deep.equal(await rootContract["getCertificate(string)"]("Blockchain Sub CA"));
        expect(await rootContract["getCertificateStatus(string)"](subCaCertificate[index['subject']['commonName']])).to.equal(0);
        expect(subCaCertificateCrt).to.equal(await rootContract["getCertificateFile(uint256)"](1));
        expect(subCaCertificateCrt).to.equal(await rootContract["getCertificateFile(string)"]("Blockchain Sub CA"));
    });

    it("Simple PKI Contract", async function () {
        // Deploy Root CA
        const PKI = await ethers.getContractFactory("SimplePKI");
        const [rootCA, subCA, user, rejectUser] = await ethers.getSigners();
        const rootContract = await PKI.deploy();
        await rootContract.deployed();
        expect(await rootContract.owner()).to.equal(rootCA.address);


        // fill root ca certificate values
        rootCaCertificate[index["extensions"]["contractAddress"]] = rootContract.address;
        rootCaCertificate[index["extensions"]["subjectWalletAddress"]] = rootCA.address;

        // generate a self signed certificate
        var { pem } = await issueCertificate(rootCaCertificate, rootCaCertificate, rootCaPrivateKey, passphrase);
        const rootCaCertificateCrt = pem;
        fs.writeFileSync('rootCaCertificate.crt', rootCaCertificateCrt);

        // assign CaCertificate in the Root CA smartcontract
        await rootContract.populateCaCertificate(pem);
        expect(rootCaCertificateCrt).to.equal(await rootContract.caCertificate());

        // generate a CSR for sub CA
        const subCaCSR = await generateCSR(subCaCertificate, subCaPublicKey, subCaPrivateKey, passphrase);
        fs.writeFileSync('subCaCSR.csr', subCaCSR);

        // Should request CA Certificate
        const subCaRequestTx = await rootContract.connect(subCA).requestCertificate(subCaCSR);
        const subCaReceipt = await subCaRequestTx.wait();
        const SubCaCertificateRequestedEvent = subCaReceipt.events.find(event => event.event === "CertificateRequested");
        const subCaSerialNumber = SubCaCertificateRequestedEvent.args.serialNumber;
        expect(subCaSerialNumber).to.equal(1);
        expect(await rootContract["getCertificateStatus(uint256)"](subCaSerialNumber)).to.equal(0);

        // Deploy Sub CA
        const subCaContract = await PKI.connect(rootCA).deploy();
        expect(await subCaContract.owner()).to.equal(rootCA.address);

        // root issuing a certificate
        const subCaCSRFromContract = await rootContract.getPendingCertificate(); // the returned array is not extensible
        const subCaSerialNumberFromContract = await rootContract.oldestPendingCertificateSerialNumber();
        const subCaWalletAddress = await rootContract.getCertificateRequester(subCaSerialNumberFromContract);
        var { pem } = await issueCertificateFromCSR(rootCaCertificate, subCaCSRFromContract, rootCaPrivateKey, passphrase, subCaWalletAddress, subCaContract.address, subCaSerialNumberFromContract);
        const subCaCertificateCrt = pem;
        fs.writeFileSync('subCaCertificate.crt', subCaCertificateCrt);

        // TODO, get common name ideally from the CSR
        // Should Issue CA Certificate
        await rootContract.issuePendingCertificate(pem, [subCaCertificate[index['subject']['commonName']]]);
        expect(await rootContract["getCertificateStatus(uint256)"](subCaSerialNumber)).to.equal(1);

        // assign CaCertificate in the Sub CA smartcontract
        await subCaContract.populateCaCertificate(subCaCertificateCrt);
        expect(subCaCertificateCrt).to.equal(await subCaContract.caCertificate());

        // Transfer owner
        await subCaContract.connect(rootCA).transferOwnership(subCA.address);
        expect(await subCaContract.owner()).to.equal(subCA.address);

        // generate a CSR for user
        const userCSR = await generateCSR(userCertificate, userPublicKey, userPrivateKey, passphrase);
        fs.writeFileSync('userCSR.csr', userCSR);

        // Should request and issue user Certificate
        const userRequestTx = await subCaContract.connect(user).requestCertificate(userCSR);
        const userReceipt = await userRequestTx.wait();
        const userCertificateRequestedEvent = userReceipt.events.find(event => event.event === "CertificateRequested");
        const userSerialNumber = userCertificateRequestedEvent.args.serialNumber;
        expect(userSerialNumber).to.equal(1);
        expect(await subCaContract["getCertificateStatus(uint256)"](userSerialNumber)).to.equal(0);

        // sub CA issuing a certificate
        const userCSRFromContract = await subCaContract.connect(subCA).getPendingCertificate();
        const userSerialNumberFromContract = await subCaContract.connect(subCA).oldestPendingCertificateSerialNumber();
        const userWalletAddress = await subCaContract.connect(subCA).getCertificateRequester(userSerialNumberFromContract);
        var { pem } = await issueCertificateFromCSR(subCaCertificate, userCSRFromContract, userPrivateKey, passphrase, userWalletAddress, "", userSerialNumberFromContract);
        const userCertificateCrt = pem;
        fs.writeFileSync('subCaCertificate.crt', userCertificateCrt);

        await subCaContract.connect(subCA).issuePendingCertificate(pem, [userCertificate[index['subject']['commonName']]]);
        expect(await subCaContract["getCertificateStatus(uint256)"](userSerialNumber)).to.equal(1);

        // Revoke user
        await subCaContract.connect(subCA).revokeCertificate(userSerialNumber);
        expect(await subCaContract["getCertificateStatus(uint256)"](userSerialNumber)).to.equal(2);

        // generate a CSR for sub CA
        const rejectUserCSR = await generateCSR(rejectUserCertificate, rejectUserPublicKey, rejectUserPrivateKey, passphrase);
        fs.writeFileSync('rejectUserCSR.csr', rejectUserCSR);

        // rejectPendingCertificate
        const rejectUserRequestTx = await subCaContract.connect(rejectUser).requestCertificate(rejectUserCSR);
        const rejectUserReceipt = await rejectUserRequestTx.wait();
        const rejectUserCertificateRequestedEvent = rejectUserReceipt.events.find(event => event.event === "CertificateRequested");
        const rejectUserSerialNumber = rejectUserCertificateRequestedEvent.args.serialNumber;
        expect(rejectUserSerialNumber).to.equal(2);
        await subCaContract.connect(subCA).rejectPendingCertificate();
        expect(await subCaContract["getCertificateStatus(uint256)"](rejectUserSerialNumber)).to.equal(3);

        // Other function
        // getCertificate Name
        expect(subCaCertificateCrt).to.equal(await rootContract["getCertificate(string)"]("Blockchain Sub CA"));
        expect(await rootContract["getCertificateStatus(string)"](subCaCertificate[index['subject']['commonName']])).to.equal(0);
        expect(subCaCertificateCrt).to.equal(await rootContract["getCertificate(uint256)"](1));
    });


});

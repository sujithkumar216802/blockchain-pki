const { expect } = require("chai");
const { ethers } = require("hardhat");
const { generateKeyPairSync, createPublicKey, createHash } = require('crypto');

describe("PKI", function () {

    function generateKeys() {
        const { publicKey, privateKey } = generateKeyPairSync('ec', {
            namedCurve: 'secp256k1',
            publicKeyEncoding: {
                type: 'spki',
                format: 'pem'
            },
            privateKeyEncoding: {
                type: 'pkcs8',
                format: 'pem',
                cipher: 'aes-256-cbc',
                passphrase: 'top secret'
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
        return { hexPublicKey, privateKey, subjectKeyIdentifier };
    }

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

    // const keys = ["SubjectCommonName", "SubjectOrganization", "SubjectLocality", "SubjectState", "SubjectCountry", "IssuerCommonName", "IssuerOrganization", "IssuerLocality", "IssuerState", "IssuerCountry", "ValidityNotBefore", "ValidityNotAfter", "DnsNames", "IpAddresses", "EmailAddresses", "URIs", "PublicKeyAlgorithm", "PublicKeySize", "PublicKeyValue", "Version", "SerialNumber", "SignatureAlgorithm", "SHA1", "SHA256", "IsCA", "PathLengthConstraint", "SubjectAddress", "IssuerAddress", "BlockchainName", "CaAddress", "SubjectKeyIdentifier", "AuthorityKeyIdentifier", "Signature"];

    var { hexPublicKey, privateKey, subjectKeyIdentifier } = generateKeys();
    var rootCaCertificate = ["Blockchain Root CA", "Root CA", "TRZ", "TN", "IN", "Blockchain Root CA", "Root CA", "TRZ", "TN", "IN", "1681161711", "1781161711", "", "", "", "", "", "", "", "3", "0", "sha256WithRSAEncryption", "sha1", "sha256", "true", "0", "", "", "Sepolia", "", "SubjectKeyIdentifier", "AuthorityKeyIdentifier", "Signature"];
    rootCaCertificate[index['publicKeyInfo']['publicKey']] = hexPublicKey;
    rootCaCertificate[index['publicKeyInfo']['keySize']] = '256';
    rootCaCertificate[index['publicKeyInfo']['algorithm']] = 'Elliptic Curve';
    rootCaCertificate[index['subjectKeyIdentifier']] = subjectKeyIdentifier;

    var { hexPublicKey, privateKey, subjectKeyIdentifier } = generateKeys();
    var subCaCertificate = ["Blockchain Sub CA", "Sub CA", "TRZ", "TN", "IN", "", "", "", "", "", "1681161711", "1781161711", "", "", "", "", "", "", "", "3", "", "sha256WithRSAEncryption", "sha1", "sha256", "true", "0", "", "", "Sepolia", "", "SubjectKeyIdentifier", "AuthorityKeyIdentifier", "Signature"];
    subCaCertificate[index['publicKeyInfo']['publicKey']] = hexPublicKey;
    subCaCertificate[index['publicKeyInfo']['keySize']] = '256';
    subCaCertificate[index['publicKeyInfo']['algorithm']] = 'Elliptic Curve';
    subCaCertificate[index['subjectKeyIdentifier']] = subjectKeyIdentifier;

    var { hexPublicKey, privateKey, subjectKeyIdentifier } = generateKeys();
    var userCertificate = ["Blockchain User 1", "User", "TRZ", "TN", "IN", "", "", "", "", "", "1681161711", "1781161711", "", "", "", "", "", "", "", "3", "", "sha256WithRSAEncryption", "sha1", "sha256", "true", "0", "", "", "Sepolia", "", "SubjectKeyIdentifier", "AuthorityKeyIdentifier", "Signature"];
    userCertificate[index['publicKeyInfo']['publicKey']] = hexPublicKey;
    userCertificate[index['publicKeyInfo']['keySize']] = '256';
    userCertificate[index['publicKeyInfo']['algorithm']] = 'Elliptic Curve';
    userCertificate[index['subjectKeyIdentifier']] = subjectKeyIdentifier;

    var { hexPublicKey, privateKey, subjectKeyIdentifier } = generateKeys();
    var rejectUserCertificate = ["Blockchain User 2", "User", "TRZ", "TN", "IN", "", "", "", "", "", "1681161711", "1781161711", "", "", "", "", "", "", "", "3", "", "sha256WithRSAEncryption", "sha1", "sha256", "true", "0", "", "", "Sepolia", "", "SubjectKeyIdentifier", "AuthorityKeyIdentifier", "Signature"];
    rejectUserCertificate[index['publicKeyInfo']['publicKey']] = hexPublicKey;
    rejectUserCertificate[index['publicKeyInfo']['keySize']] = '256';
    rejectUserCertificate[index['publicKeyInfo']['algorithm']] = 'Elliptic Curve';
    rejectUserCertificate[index['subjectKeyIdentifier']] = subjectKeyIdentifier;

    console.log(rootCaCertificate);
    console.log(subCaCertificate);
    console.log(userCertificate);
    console.log(rejectUserCertificate);

    // A single test is being used to preserve state instead of having different tests which resets the state of the contract
    it("Everything", async function () {
        // Deploy Root CA
        const PKI = await ethers.getContractFactory("PKI");
        const [rootCA, subCA, user, rejectUser] = await ethers.getSigners();
        const rootContract = await PKI.deploy();
        await rootContract.deployed();
        expect(await rootContract.owner()).to.equal(rootCA.address);

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



        // Deploy Sub CA
        const subCaContract = await PKI.connect(rootCA).deploy();
        expect(await subCaContract.owner()).to.equal(rootCA.address);

        // Should Issue CA Certificate
        await rootContract.issuePendingCertificate("toBeFilled", subCaContract.address);
        expect(await rootContract.getCertificateStatus(subCaSerialNumber)).to.equal(1);

        // assign CaCertificate in the Sub CA smartcontract
        var tempSubCaCertificate = await rootContract["getCertificate(uint256)"](1);
        await subCaContract.populateCaCertificate(tempSubCaCertificate);
        expect(tempSubCaCertificate).to.deep.equal(await subCaContract.getCaCertificate());

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
        expect(tempSubCaCertificate).to.deep.equal(await rootContract["getCertificate(string)"]("Blockchain Sub CA"));

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

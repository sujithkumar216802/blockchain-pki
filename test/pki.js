const { expect } = require("chai");
const { ethers } = require("hardhat");

describe("PKI", function () {

    var rootCaCertificate = {
        "subject": {
            "commonName": "Blockchain Root CA",
            "organization": "Root CA",
            "locality": "TRZ",
            "state": "TN",
            "country": "IN",
        },
        "issuer": {
            "commonName": "Blockchain Root CA",
            "organization": "Root CA",
            "locality": "TRZ",
            "state": "TN",
            "country": "IN",
        },
        "validity": {
            "notBefore": 1681161711,
            "notAfter": 1781161711,
        },
        "subjectAltName": {
            "dnsNames": [],
            "ipAddresses": [],
            "emailAddresses": [],
            "uris": [],
        },
        "publicKeyInfo": {
            "algorithm": "rsaEncryption",
            "keySize": 2048,
            "publicKey": "toBeFilled"
        },
        "miscellaneous": {
            "version": 3,
            "serialNumber": 0,
            "signatureAlgorithm": "sha256WithRSAEncryption",
        },
        "fingerprints": {
            "sha1": "toBeFilled",
            "_sha256": "toBeFilled",
        },
        "basicConstraints": {
            "isCA": true,
            "pathLenConstraint": 0,
        },
        "keyUsage": {
            "digitalSignature": true,
            "contentCommitment": true,
            "keyEncipherment": true,
            "dataEncipherment": true,
            "keyAgreement": true,
            "keyCertSign": true,
            "cRLSign": true,
            "encipherOnly": true,
            "decipherOnly": true,
        },
        "subjectKeyIdentifier": "0",
        "authorityKeyIdentifier": "0",
        "extensions": {
            "subjectAddress": "",
            "issuerAddress": "",
            "blockchainName": "solana",
            "caAddress": "",
        },
        "signature": "0",
    }

    var subCaCertificate = {
        "subject": {
            "commonName": "Blockchain Sub CA",
            "organization": "Sub CA",
            "locality": "TRZ",
            "state": "TN",
            "country": "IN",
        },
        "validity": {
            "notBefore": 1681161711,
            "notAfter": 1781161711,
        },
        "subjectAltName": {
            "dnsNames": [],
            "ipAddresses": [],
            "emailAddresses": [],
            "uris": [],
        },
        "publicKeyInfo": {
            "algorithm": "rsaEncryption",
            "keySize": 2048,
            "publicKey": "toBeFilled"
        },
        "miscellaneous": {
            "version": 3,
            "serialNumber": 0,
            "signatureAlgorithm": "sha256WithRSAEncryption",
        },
        "fingerprints": {
            "sha1": "toBeFilled",
            "_sha256": "toBeFilled",
        },
        "basicConstraints": {
            "isCA": true,
            "pathLenConstraint": 0,
        },
        "keyUsage": {
            "digitalSignature": true,
            "contentCommitment": true,
            "keyEncipherment": true,
            "dataEncipherment": true,
            "keyAgreement": true,
            "keyCertSign": true,
            "cRLSign": true,
            "encipherOnly": true,
            "decipherOnly": true,
        },
        "subjectKeyIdentifier": "0",
        "authorityKeyIdentifier": "0",
        "signature": "0",
    }

    var userCertificate = {
        "subject": {
            "commonName": "Blockchain User 1",
            "organization": "Users",
            "locality": "TRZ",
            "state": "TN",
            "country": "IN",
        },
        "validity": {
            "notBefore": 1681161711,
            "notAfter": 1781161711,
        },
        "subjectAltName": {
            "dnsNames": [],
            "ipAddresses": [],
            "emailAddresses": [],
            "uris": [],
        },
        "publicKeyInfo": {
            "algorithm": "rsaEncryption",
            "keySize": 2048,
            "publicKey": "toBeFilled"
        },
        "miscellaneous": {
            "version": 3,
            "serialNumber": 0,
            "signatureAlgorithm": "sha256WithRSAEncryption",
        },
        "fingerprints": {
            "sha1": "toBeFilled",
            "_sha256": "toBeFilled",
        },
        "basicConstraints": {
            "isCA": true,
            "pathLenConstraint": 0,
        },
        "keyUsage": {
            "digitalSignature": true,
            "contentCommitment": true,
            "keyEncipherment": true,
            "dataEncipherment": true,
            "keyAgreement": true,
            "keyCertSign": true,
            "cRLSign": true,
            "encipherOnly": true,
            "decipherOnly": true,
        },
        "subjectKeyIdentifier": "0",
        "authorityKeyIdentifier": "0",
        "signature": "0",
    }

    var rejectUserCertificate = {
        "subject": {
            "commonName": "Blockchain User 2",
            "organization": "Users",
            "locality": "TRZ",
            "state": "TN",
            "country": "IN",
        },
        "validity": {
            "notBefore": 1681161711,
            "notAfter": 1781161711,
        },
        "subjectAltName": {
            "dnsNames": [],
            "ipAddresses": [],
            "emailAddresses": [],
            "uris": [],
        },
        "publicKeyInfo": {
            "algorithm": "rsaEncryption",
            "keySize": 2048,
            "publicKey": "toBeFilled"
        },
        "miscellaneous": {
            "version": 3,
            "serialNumber": 0,
            "signatureAlgorithm": "sha256WithRSAEncryption",
        },
        "fingerprints": {
            "sha1": "toBeFilled",
            "_sha256": "toBeFilled",
        },
        "basicConstraints": {
            "isCA": true,
            "pathLenConstraint": 0,
        },
        "keyUsage": {
            "digitalSignature": true,
            "contentCommitment": true,
            "keyEncipherment": true,
            "dataEncipherment": true,
            "keyAgreement": true,
            "keyCertSign": true,
            "cRLSign": true,
            "encipherOnly": true,
            "decipherOnly": true,
        },
        "subjectKeyIdentifier": "0",
        "authorityKeyIdentifier": "0",
        "signature": "0",
    }

    function compareCertificate(obj1, obj2) {
        Object.keys(obj1).forEach((key) => {
            if (typeof obj1[key] === 'object') {
                compareCertificate(obj1[key], obj2[key]);
            } else {
                expect(obj1[key]).to.equal(obj2[key]);
            }
        });
    }

    // A single test is being used to preserve state instead of having different tests which resets the state of the contract
    it("Everything", async function () {
        // Deploy Root CA
        const PKI = await ethers.getContractFactory("PKI");
        const [rootCA, subCA, user, rejectUser] = await ethers.getSigners();
        const rootContract = await PKI.deploy();
        await rootContract.deployed();
        expect(await rootContract.owner()).to.equal(rootCA.address);

        // assign CaCertificate in the Root CA smartcontract
        rootCaCertificate["extensions"]["caAddress"] = rootContract.address;
        rootCaCertificate["extensions"]["issuerAddress"] = rootCA.address;
        rootCaCertificate["extensions"]["subjectAddress"] = rootCA.address;
        await rootContract.populateCaCertificate(rootCaCertificate);
        compareCertificate(rootCaCertificate, await rootContract.caCertificate());

        // Should request and issue CA Certificate
        const subCaRequestTx = await rootContract.connect(subCA).requestCertificate(subCaCertificate["subject"], subCaCertificate["validity"], subCaCertificate["subjectAltName"], subCaCertificate["publicKeyInfo"], subCaCertificate["basicConstraints"], subCaCertificate["keyUsage"], subCaCertificate["subjectKeyIdentifier"]);
        const subCaReceipt = await subCaRequestTx.wait();
        const SubCaCertificateRequestedEvent = subCaReceipt.events.find(event => event.event === "CertificateRequested");
        const subCaSerialNumber = SubCaCertificateRequestedEvent.args.serialNumber;
        expect(subCaSerialNumber).to.equal(1);
        expect(await rootContract.getCertificateStatus(subCaSerialNumber)).to.equal(0);
        await rootContract.issueCertificate("toBeFilled");
        expect(await rootContract.getCertificateStatus(subCaSerialNumber)).to.equal(1);



        // Deploy Sub CA
        const subCaContract = await PKI.connect(rootCA).deploy();
        expect(await subCaContract.owner()).to.equal(rootCA.address);

        // assign CaCertificate in the Sub CA smartcontract
        var tempSubCaCertificate = await rootContract["getCertificate(uint256)"](1);
        await subCaContract.populateCaCertificate(tempSubCaCertificate); // TODO
        compareCertificate(tempSubCaCertificate, await subCaContract.caCertificate());

        // Transfer owner
        await subCaContract.connect(rootCA).transferOwnership(subCA.address);
        expect(await subCaContract.owner()).to.equal(subCA.address);

        // Should request and issue user Certificate
        const userRequestTx = await subCaContract.connect(user).requestCertificate(userCertificate["subject"], userCertificate["validity"], userCertificate["subjectAltName"], userCertificate["publicKeyInfo"], userCertificate["basicConstraints"], userCertificate["keyUsage"], userCertificate["subjectKeyIdentifier"]);
        const userReceipt = await userRequestTx.wait();
        const userCertificateRequestedEvent = userReceipt.events.find(event => event.event === "CertificateRequested");
        const userSerialNumber = userCertificateRequestedEvent.args.serialNumber;
        expect(userSerialNumber).to.equal(1);
        expect(await subCaContract.getCertificateStatus(userSerialNumber)).to.equal(0);
        await subCaContract.connect(subCA).issueCertificate("toBeFilled");
        expect(await subCaContract.getCertificateStatus(userSerialNumber)).to.equal(1);

        // Revoke user
        await subCaContract.connect(subCA).revokeCertificate(userSerialNumber);
        expect(await subCaContract.getCertificateStatus(userSerialNumber)).to.equal(2);

        // Other function
        // getCertificate Name
        compareCertificate(tempSubCaCertificate, await rootContract["getCertificate(string)"]("Blockchain Sub CA"));

        // rejectPendingCertificate
        // Should request and issue user Certificate
        const rejectUserRequestTx = await subCaContract.connect(rejectUser).requestCertificate(userCertificate["subject"], rejectUserCertificate["validity"], rejectUserCertificate["subjectAltName"], rejectUserCertificate["publicKeyInfo"], rejectUserCertificate["basicConstraints"], rejectUserCertificate["keyUsage"], rejectUserCertificate["subjectKeyIdentifier"]);
        const rejectUserReceipt = await rejectUserRequestTx.wait();
        const rejectUserCertificateRequestedEvent = rejectUserReceipt.events.find(event => event.event === "CertificateRequested");
        const rejectUserSerialNumber = rejectUserCertificateRequestedEvent.args.serialNumber;
        expect(rejectUserSerialNumber).to.equal(2);
        await subCaContract.connect(subCA).rejectPendingCertificate();
        expect(await subCaContract.getCertificateStatus(rejectUserSerialNumber)).to.equal(3);
    });
});

const { expect } = require("chai");
const { ethers } = require("hardhat");
// const { generateKeyPairSync } = require('crypto');

describe("PKI", function () {

    // const { publicKey, privateKey } = generateKeyPairSync('rsa', {
    //     modulusLength: 2048,
    //     publicExponent: 0x10101,
    //     publicKeyEncoding: {
    //         type: 'spki',
    //         format: 'der',
    //     },
    //     privateKeyEncoding: {
    //         type: 'pkcs8',
    //         format: 'der'
    //     }
    // });

    // // Prints asymmetric key pair
    // console.log("The public key is: ", publicKey);
    // console.log();
    // console.log("The private key is: ", privateKey);

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

    var rootCaCertificate = ["Blockchain Root CA", "Root CA", "TRZ", "TN", "IN", "Blockchain Root CA", "Root CA", "TRZ", "TN", "IN", "1681161711", "1781161711", "", "", "", "", "rsaEncryption", "2048", "publickeyValue", "3", "0", "sha256WithRSAEncryption", "sha1", "sha256", "true", "0", "", "", "solana", "", "SubjectKeyIdentifier", "AuthorityKeyIdentifier", "Signature"];

    var subCaCertificate = ["Blockchain Sub CA", "Sub CA", "TRZ", "TN", "IN", "", "", "", "", "", "1681161711", "1781161711", "", "", "", "", "rsaEncryption", "2048", "publickeyValue", "3", "", "sha256WithRSAEncryption", "sha1", "sha256", "true", "0", "", "", "solana", "", "SubjectKeyIdentifier", "AuthorityKeyIdentifier", "Signature"];

    var userCertificate = ["Blockchain User 1", "User", "TRZ", "TN", "IN", "", "", "", "", "", "1681161711", "1781161711", "", "", "", "", "rsaEncryption", "2048", "publickeyValue", "3", "", "sha256WithRSAEncryption", "sha1", "sha256", "true", "0", "", "", "solana", "", "SubjectKeyIdentifier", "AuthorityKeyIdentifier", "Signature"];

    var rejectUserCertificate = ["Blockchain User 2", "User", "TRZ", "TN", "IN", "", "", "", "", "", "1681161711", "1781161711", "", "", "", "", "rsaEncryption", "2048", "publickeyValue", "3", "", "sha256WithRSAEncryption", "sha1", "sha256", "true", "0", "", "", "solana", "", "SubjectKeyIdentifier", "AuthorityKeyIdentifier", "Signature"];

    // function compareCertificate(obj1, obj2) {
    //     Object.keys(obj1).forEach((key) => {
    //         if (typeof obj1[key] === 'object') {
    //             compareCertificate(obj1[key], obj2[key]);
    //         } else {
    //             expect(obj1[key]).to.equal(obj2[key]);
    //         }
    //     });
    // }

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
        // compareCertificate(rootCaCertificate, await rootContract.caCertificate());

        // Should request and issue CA Certificate
        const subCaRequestTx = await rootContract.connect(subCA).requestCertificate(subCaCertificate);
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
        await subCaContract.populateCaCertificate(tempSubCaCertificate);
        // compareCertificate(tempSubCaCertificate, await subCaContract.caCertificate());

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
        await subCaContract.connect(subCA).issueCertificate("toBeFilled");
        expect(await subCaContract.getCertificateStatus(userSerialNumber)).to.equal(1);

        // Revoke user
        await subCaContract.connect(subCA).revokeCertificate(userSerialNumber);
        expect(await subCaContract.getCertificateStatus(userSerialNumber)).to.equal(2);

        // Other function
        // getCertificate Name
        // compareCertificate(tempSubCaCertificate, await rootContract["getCertificate(string)"]("Blockchain Sub CA"));

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

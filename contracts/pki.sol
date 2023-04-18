// SPDX-License-Identifier: MIT
pragma solidity ^0.8.18;
import "./owned.sol";

contract PKI is owned {
    
    struct Identity {
        string commonName;
        string organization;
        string locality;
        string state;
        string country;
    }

    struct Validity {
        uint256 notBefore;
        uint256 notAfter;
    }

    struct SubjectAltName {
        string[] dnsNames;
        string[] ipAddresses;
        string[] emailAddresses;
        string[] uris;
    }

    struct PublicKeyInfo {
        string algorithm;
        uint32 keySize;
        string publicKey;
    }

    struct Miscellaneous {
        uint8 version;
        uint256 serialNumber;
        string signatureAlgorithm;
    }

    struct Fingerprints {
        string sha1;
        string _sha256;
    }

    struct BasicConstraints {
        bool isCA;
        uint256 pathLenConstraint;
    }

    struct KeyUsage {
        bool digitalSignature;
        bool contentCommitment;
        bool keyEncipherment;
        bool dataEncipherment;
        bool keyAgreement;
        bool keyCertSign;
        bool cRLSign;
        bool encipherOnly;
        bool decipherOnly;
    }

    struct Extensions {
        address subjectAddress;
        address issuerAddress;
        string blockchainName;
        address caAddress; // if the certificate is of a CA, it holds smart contract address of the CA
    }

    struct Certificate {
        Identity subject;
        Identity issuer;
        Validity validity;
        SubjectAltName subjectAltName;
        PublicKeyInfo publicKeyInfo;
        Miscellaneous miscellaneous;
        Fingerprints fingerprints; // sha of the entire certificate is DER form
        BasicConstraints basicConstraints;
        KeyUsage keyUsage;
        string subjectKeyIdentifier; // sha 1 of public key of subject
        string authorityKeyIdentifier; // sha 1 of public key of issuer
        Extensions extensions;
        string signature;
    }

    enum Status {
        Pending,
        Issued,
        Revoked,
        Rejected,
        Expired
    }

    uint _oldestPendingCertificate = 1;
    Certificate public caCertificate;
    Certificate[] certificates;
    mapping(string => uint) nameToSerialNumber; // common and alt name to serial number
    mapping(uint => Status) certificateStatus;

    function populateCaCertificate(Certificate memory cert) public onlyOwner {
        caCertificate = cert;
    }

    event CertificateRequested(uint serialNumber, string commonName);

    // ask CA to issue a certificate
    function requestCertificate(
        Identity memory subject,
        Validity memory validity,
        SubjectAltName memory subjectAltName,
        PublicKeyInfo memory publicKeyInfo,
        BasicConstraints memory basicConstraints,
        KeyUsage memory keyUsage,
        string memory subjectKeyIdentifier
    ) public {
        // checks

        // subject begins //
        require(
            bytes(subject.commonName).length > 0,
            "Common name is required"
        );
        require(
            bytes(subject.organization).length > 0,
            "Organization is required"
        );
        require(bytes(subject.locality).length > 0, "Locality is required");
        require(bytes(subject.state).length > 0, "State is required");
        require(bytes(subject.country).length > 0, "Country is required");
        // subject ends //

        // validity begins //
        require(
            validity.notAfter > validity.notBefore,
            "Validity period is invalid"
        );
        require(
            validity.notAfter > block.timestamp,
            "Certificate is already expired"
        );
        // validity ends //

        // subjectAltName begins //
        // subjectAltName ends //

        // public key info begins //
        require(
            bytes(publicKeyInfo.algorithm).length > 0,
            "Public key algorithm is required"
        );
        require(
            bytes(publicKeyInfo.publicKey).length > 0,
            "Public key is required"
        );
        require(
            bytes(subjectKeyIdentifier).length > 0,
            "Subject key identifier is required"
        );
        // public key info ends //

        // basic constraints begins //
        require(
            basicConstraints.pathLenConstraint >= 0,
            "Path length constraint is invalid");
        // basic constraints ends //

        // key usage begins //
        // key usage ends //

        certificateStatus[certificates.length + 1] = Status.Pending;
        emit CertificateRequested(certificates.length + 1, subject.commonName);
        certificates.push(
            Certificate(
                subject,
                caCertificate.subject,
                validity,
                subjectAltName,
                publicKeyInfo,
                Miscellaneous(
                    3,
                    certificates.length + 1,
                    "SHA-256 with RSA Encryption"
                ),
                Fingerprints("", ""), // fill this while issuing the certificate
                basicConstraints,
                keyUsage,
                subjectKeyIdentifier,
                caCertificate.subjectKeyIdentifier, // authority key identifier
                Extensions(msg.sender, caCertificate.extensions.subjectAddress, caCertificate.extensions.blockchainName, address(0)), // look into miscellaneous vs extensions. half of them are provided... check the subject key stuff while creating a certificate
                "" // signature
            )
        );
    }

    // rejects the oldest pending certificate
    function rejectPendingCertificate() public onlyOwner {
        require(certificateStatus[_oldestPendingCertificate] == Status.Pending);
        certificateStatus[_oldestPendingCertificate] = Status.Rejected;
        _oldestPendingCertificate++;
    }

    // TODO: fingerprint, check for existing altnames
    // issues the oldest pending certificate
    function issueCertificate(string memory signature) public onlyOwner {
        certificates[_oldestPendingCertificate - 1].signature = signature;
        certificateStatus[_oldestPendingCertificate] = Status.Issued;
        nameToSerialNumber[certificates[_oldestPendingCertificate - 1].subject.commonName] = _oldestPendingCertificate;
        uint i = 0;
        uint j = certificates[_oldestPendingCertificate - 1].subjectAltName.dnsNames.length;
        for(; i < j; i++) {
            nameToSerialNumber[certificates[_oldestPendingCertificate - 1].subjectAltName.dnsNames[i]] = _oldestPendingCertificate;
        }
        i = 0;
        j = certificates[_oldestPendingCertificate - 1].subjectAltName.ipAddresses.length;
        for(; i < j; i++) {
            nameToSerialNumber[certificates[_oldestPendingCertificate - 1].subjectAltName.ipAddresses[i]] = _oldestPendingCertificate;
        }
        i = 0;
        j = certificates[_oldestPendingCertificate - 1].subjectAltName.emailAddresses.length;
        for(; i < j; i++) {
            nameToSerialNumber[certificates[_oldestPendingCertificate - 1].subjectAltName.emailAddresses[i]] = _oldestPendingCertificate;
        }
        i = 0;
        j = certificates[_oldestPendingCertificate - 1].subjectAltName.uris.length;
        for(; i < j; i++) {
            nameToSerialNumber[certificates[_oldestPendingCertificate - 1].subjectAltName.uris[i]] = _oldestPendingCertificate;
        }
        _oldestPendingCertificate++;
    }

    function getCertificate(
        uint serialNumber
    ) public view returns (Certificate memory) {
        require(serialNumber <= certificates.length);
        return certificates[serialNumber - 1];
    }

    function getCertificate(
        string memory name
    ) public view returns (Certificate memory) {
        require(nameToSerialNumber[name] > 0, "No certificate for this name");
        return certificates[nameToSerialNumber[name] - 1];
    }

    function revokeCertificate(uint serialNumber) public onlyOwner {
        require(certificateStatus[serialNumber] == Status.Issued);
        require(serialNumber <= certificates.length);
        certificateStatus[serialNumber] = Status.Revoked;
    }

    function getPendingCertificate()
        public
        view
        onlyOwner
        returns (Certificate memory)
    {
        require(
            _oldestPendingCertificate <= certificates.length,
            "No pending certificates"
        );
        return certificates[_oldestPendingCertificate - 1];
    }

    // 0 - pending, 1 - issued, 2 - revoked, 3 - rejected, 4 - expired
    function getCertificateStatus(uint serialNumber) public view returns (uint) {
        require(serialNumber <= certificates.length);
        return uint(certificateStatus[serialNumber]);
    }
}

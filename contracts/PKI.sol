// SPDX-License-Identifier: MIT
pragma solidity ^0.8.18;
import "./owned.sol";
import "./strings.sol";

contract PKI is owned {
    // struct Identity {
    //     string commonName; 0 5
    //     string organization; 1 6
    //     string locality; 2 7
    //     string state; 3 8
    //     string country; 4 9
    // }

    // struct Validity {
    //     uint256 notBefore; 10
    //     uint256 notAfter; 11
    // }

    // struct SubjectAltName {
    //     string[] dnsNames; 12
    //     string[] ipAddresses; 13
    //     string[] emailAddresses; 14
    //     string[] uris; 15
    // }

    // struct PublicKeyInfo {
    //     string algorithm; 16
    //     uint32 keySize; 17
    //     string publicKey; 18
    // }

    // struct Miscellaneous {
    //     uint8 version; 19
    //     uint256 serialNumber; 20
    //     string signatureAlgorithm; 21
    // }

    // struct Fingerprints {
    //     string sha1; 22
    //     string _sha256; 23
    // }

    // struct BasicConstraints {
    //     bool isCA; 24
    //     uint256 pathLenConstraint; 25
    // }

    // struct KeyUsage {
    //     bool digitalSignature;
    //     bool contentCommitment;
    //     bool keyEncipherment;
    //     bool dataEncipherment;
    //     bool keyAgreement;
    //     bool keyCertSign;
    //     bool cRLSign;
    //     bool encipherOnly;
    //     bool decipherOnly;
    // }

    // struct Extensions {
    //     address subjectWalletAddress; 26 // wallet address of user
    //     address issuerContractAddress; 27 // holds the smart contract address of the issuer ca
    //     string blockchainName; 28
    //     address contractAddress; 29 // if the certificate is of a CA, it holds smart contract address of the CA
    // }

    // struct Certificate {
    //     Identity subject; // 5
    //     Identity issuer; // 5
    //     Validity validity; // 2
    //     SubjectAltName subjectAltName; // 4
    //     PublicKeyInfo publicKeyInfo; // 3
    //     Miscellaneous miscellaneous; // 3
    //     Fingerprints fingerprints; // sha of the entire certificate is DER form // 2
    //     BasicConstraints basicConstraints; // 2
    //     KeyUsage keyUsage; // 9
    //     string subjectKeyIdentifier; 30 // sha 1 of public key of subject // 1
    //     string authorityKeyIdentifier; 31 // sha 1 of public key of issuer // 1
    //     Extensions extensions; // 4
    //     string signature; 32  // 1
    //     // total 42
    //     // using 33, ignoring KeyUsage for now
    // }

    using strings for *;

    enum Status {
        Pending,
        Issued,
        Revoked,
        Rejected,
        Expired
    }

    uint public oldestPendingCertificateSerialNumber = 1;
    string[33] caCertificate;
    string public caCertificateFile;
    string[33][] certificates; // columns then rows for initialization only
    string[] certificateFiles;
    mapping(string => uint) nameToSerialNumber; // common and alt name to serial number
    mapping(uint => Status) certificateStatus;

    function populateCaCertificate(string[33] memory cert, string memory certFile) public onlyOwner {
        caCertificate = cert;
        caCertificateFile = certFile;
    }

    function getCaCertificate() public view returns (string[33] memory) {
        return caCertificate;
    }

    event CertificateRequested(uint serialNumber, string commonName);

    // ask CA to issue a certificate
    function requestCertificate(string[33] memory cert) public {
        // checks
        // subject begins //
        require(bytes(cert[0]).length > 0, "Common name is required");
        require(bytes(cert[1]).length > 0, "Organization is required");
        require(bytes(cert[2]).length > 0, "Locality is required");
        require(bytes(cert[3]).length > 0, "State is required");
        require(bytes(cert[4]).length > 0, "Country is required");
        // subject ends //

        // validity begins //
        uint notBefore = stringToUint(cert[10]);
        uint notAfter = stringToUint(cert[11]);
        require(notAfter > notBefore, "Validity period is invalid");
        require(notAfter > block.timestamp, "Certificate is already expired");
        // validity ends //

        // subjectAltName begins //
        // subjectAltName ends //

        // public key info begins //
        require(bytes(cert[16]).length > 0, "Public key algorithm is required");
        uint keySize = stringToUint(cert[17]);
        require(keySize > 0, "Public key size is invalid");
        require(bytes(cert[18]).length > 0, "Public key is required");
        // public key info ends //

        // basic constraints begins //
        require(stringIsBool(cert[24]), "isCa is invalid");
        uint pathLenConstraint = stringToUint(cert[25]);
        require(pathLenConstraint >= 0, "Path length constraint is invalid");
        // basic constraints ends //

        // key usage begins //
        // key usage ends //

        // others begins //
        // others ends //

        certificateStatus[certificates.length + 1] = Status.Pending;
        emit CertificateRequested(certificates.length + 1, cert[0]);
        cert[5] = caCertificate[0];
        cert[6] = caCertificate[1];
        cert[7] = caCertificate[2];
        cert[8] = caCertificate[3];
        cert[9] = caCertificate[4];
        cert[19] = "3";
        cert[20] = uintToString(certificates.length + 1);
        cert[21] = "ecdsa-with-SHA256";
        cert[26] = toString(msg.sender);
        cert[27] = caCertificate[29];
        cert[28] = caCertificate[28];
        cert[29] = "";
        cert[31] = caCertificate[30];
        cert[32] = "";
        certificates.push(cert);
    }

    function isPendingCertificate() public view onlyOwner returns (bool) {
        return oldestPendingCertificateSerialNumber <= certificates.length;
    }

    function getPendingCertificate()
        public
        view
        onlyOwner
        returns (string[33] memory)
    {
        require(
            oldestPendingCertificateSerialNumber <= certificates.length,
            "No pending certificates"
        );
        return certificates[oldestPendingCertificateSerialNumber - 1];
    }

    // rejects the oldest pending certificate
    function rejectPendingCertificate() public onlyOwner {
        require(isPendingCertificate(), "No pending certificates");
        certificateStatus[oldestPendingCertificateSerialNumber] = Status.Rejected;
        oldestPendingCertificateSerialNumber++;
    }

    // issues the oldest pending certificate
    function issuePendingCertificate(
        string memory signature,
        string memory contractAddress,
        string memory subjectKeyIdentifier,
        string memory certificateFile
    ) public onlyOwner {
        require(isPendingCertificate(), "No pending certificates");
        certificates[oldestPendingCertificateSerialNumber - 1][29] = contractAddress;
        certificates[oldestPendingCertificateSerialNumber - 1][30] = subjectKeyIdentifier;
        certificates[oldestPendingCertificateSerialNumber - 1][32] = signature;
        certificateFiles.push(certificateFile);
        certificateStatus[oldestPendingCertificateSerialNumber] = Status.Issued;
        nameToSerialNumber[certificates[oldestPendingCertificateSerialNumber - 1][0]] = oldestPendingCertificateSerialNumber; // commonName
        string memory temp = string.concat(certificates[oldestPendingCertificateSerialNumber - 1][12], " ");
        string memory temp1 = string.concat(temp, certificates[oldestPendingCertificateSerialNumber - 1][13]);
        string memory temp2 = string.concat(temp1, " ");
        string memory temp3 = string.concat(temp2, certificates[oldestPendingCertificateSerialNumber - 1][14]);
        string memory temp4 = string.concat(temp3, " ");
        string memory temp5 = string.concat(temp4, certificates[oldestPendingCertificateSerialNumber - 1][15]);
        string[] memory altNames = stringToStringArray(temp5, " ");
        for (uint i = 0; i < altNames.length; i++) {
            nameToSerialNumber[
                altNames[i]
            ] = oldestPendingCertificateSerialNumber;
        }
        oldestPendingCertificateSerialNumber++;
    }

    function checkExpiry(uint serialNumber) public returns (bool) {
        require(serialNumber <= certificates.length);
        uint notAfter = stringToUint(certificates[serialNumber - 1][11]);
        if(notAfter < block.timestamp) {
            certificateStatus[serialNumber] = Status.Expired;
            return true;
        }
        return false;
    }

    function getCertificateFile(
        uint serialNumber
    ) public view returns (string memory) {
        require(serialNumber <= certificateFiles.length, "certificate not issued");
        return certificateFiles[serialNumber - 1];
    }

    function getCertificateFile(
        string memory name
    ) public view returns (string memory) {
        require(nameToSerialNumber[name] > 0, "No certificate for this name");
        require(nameToSerialNumber[name] <= certificateFiles.length, "certificate not issued");
        return certificateFiles[nameToSerialNumber[name] - 1];
    }

    function getCertificate(
        uint serialNumber
    ) public view returns (string[33] memory) {
        require(serialNumber <= certificates.length, "No certificate for this serial no.");
        return certificates[serialNumber - 1];
    }

    function getCertificate(
        string memory name
    ) public view returns (string[33] memory) {
        require(nameToSerialNumber[name] > 0, "No certificate for this name");
        return certificates[nameToSerialNumber[name] - 1];
    }

    function revokeCertificate(uint serialNumber) public onlyOwner {
        require(certificateStatus[serialNumber] == Status.Issued);
        require(serialNumber <= certificates.length);
        certificateStatus[serialNumber] = Status.Revoked;
    }

    // 0 - pending, 1 - issued, 2 - revoked, 3 - rejected, 4 - expired
    function getCertificateStatus(
        uint serialNumber
    ) public view returns (uint) {
        require(serialNumber <= certificates.length);
        return uint(certificateStatus[serialNumber]);
    }

    function getCertificateStatus(
        string memory name
    ) public view returns (uint) {
        require(nameToSerialNumber[name] > 0, "No certificate for this name");
        return uint(certificateStatus[nameToSerialNumber[name] - 1]);
    }

    // Helper functions begin

    function stringToStringArray(
        string memory str,
        string memory del
    ) private pure returns (string[] memory) {
        strings.slice memory delim = del.toSlice();
        strings.slice memory s = str.toSlice();
        string[] memory parts = new string[](s.count(delim) + 1);
        for (uint i = 0; i < parts.length; i++) {
            parts[i] = s.split(delim).toString();
        }
        return parts;
    }

    // decimal string to uint
    function stringToUint(string memory s) private pure returns (uint) {
        bytes memory b = bytes(s);
        uint result = 0;
        for (uint256 i = 0; i < b.length; i++) {
            uint256 c = uint256(uint8(b[i]));
            if (c >= 48 && c <= 57) {
                result = result * 10 + (c - 48);
            }
        }
        return result;
    }

    function stringIsBool(string memory a) private pure returns (bool) {
        return ((keccak256(abi.encodePacked((a))) ==
            keccak256(abi.encodePacked(("true")))) ||
            (keccak256(abi.encodePacked((a))) ==
                keccak256(abi.encodePacked(("false")))));
    }

    function toString(address account) private pure returns (string memory) {
        return toString(abi.encodePacked(account));
    }

    // uint to hexadecimal string
    // function toString(uint256 value) public pure returns (string memory) {
    //     return toString(abi.encodePacked(value));
    // }

    function toString(bytes memory data) private pure returns (string memory) {
        bytes memory alphabet = "0123456789abcdef";

        bytes memory str = new bytes(2 + data.length * 2);
        str[0] = "0";
        str[1] = "x";
        for (uint i = 0; i < data.length; i++) {
            str[2 + i * 2] = alphabet[uint(uint8(data[i] >> 4))];
            str[3 + i * 2] = alphabet[uint(uint8(data[i] & 0x0f))];
        }
        return string(str);
    }

    function uintToString(
        uint _i
    ) private pure returns (string memory _uintAsString) {
        if (_i == 0) {
            return "0";
        }
        uint j = _i;
        uint len;
        while (j != 0) {
            len++;
            j /= 10;
        }
        bytes memory bstr = new bytes(len);
        uint k = len;
        while (_i != 0) {
            k = k - 1;
            uint8 temp = (48 + uint8(_i - (_i / 10) * 10));
            bytes1 b1 = bytes1(temp);
            bstr[k] = b1;
            _i /= 10;
        }
        return string(bstr);
    }

    // Helper functions end
}

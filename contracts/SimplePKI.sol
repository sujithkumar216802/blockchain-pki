// SPDX-License-Identifier: MIT
pragma solidity ^0.8.18;
import "./owned.sol";

contract SimplePKI is owned {

    enum Status {
        Pending,
        Issued,
        Revoked,
        Rejected,
        Expired
    }

    uint public oldestPendingCertificateSerialNumber = 1;
    string public caCertificate;
    string[] certificates;
    string[] certificatesRequests;
    address[] certificateRequester;
    mapping(string => uint) nameToSerialNumber; // common and alt name to serial number
    mapping(uint => Status) certificateStatus;

    function populateCaCertificate(string memory cert) public onlyOwner {
        caCertificate = cert;
    }

    event CertificateRequested(uint serialNumber, address requester);

    // ask CA to issue a certificate
    function requestCertificate(string memory cert) public {
        certificateStatus[certificatesRequests.length + 1] = Status.Pending;
        emit CertificateRequested(certificatesRequests.length + 1, msg.sender);
        certificatesRequests.push(cert);
        certificateRequester.push(msg.sender);
    }

    function isPendingCertificate() public view onlyOwner returns (bool) {
        return oldestPendingCertificateSerialNumber <= certificatesRequests.length;
    }
    
    function getPendingCertificate()
        public
        view
        onlyOwner
        returns (string memory)
    {
        require(
            oldestPendingCertificateSerialNumber <= certificatesRequests.length,
            "No pending certificates"
        );
        return certificatesRequests[oldestPendingCertificateSerialNumber - 1];
    }

    // rejects the oldest pending certificate
    function rejectPendingCertificate() public onlyOwner {
        require(isPendingCertificate(), "No pending certificates");
        certificateStatus[oldestPendingCertificateSerialNumber] = Status.Rejected;
        oldestPendingCertificateSerialNumber++;
    }

    // issues the oldest pending certificate
    function issuePendingCertificate(string memory certificateFile, string[] memory names) public onlyOwner {
        require(isPendingCertificate(), "No pending certificates");
        certificates.push(certificateFile);
        certificateStatus[oldestPendingCertificateSerialNumber] = Status.Issued;
        for (uint i = 0; i < names.length; i++) {
            nameToSerialNumber[names[i]] = oldestPendingCertificateSerialNumber;
        }
        oldestPendingCertificateSerialNumber++;
    }

    function getCertificateRequester(
        uint serialNumber
    ) public view returns (address) {
        require(serialNumber <= certificatesRequests.length);
        return certificateRequester[serialNumber - 1];
    }

    function getCertificate(
        uint serialNumber
    ) public view returns (string memory) {
        require(serialNumber <= certificates.length);
        return certificates[serialNumber - 1];
    }

    function getCertificate(
        string memory name
    ) public view returns (string memory) {
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
        require(serialNumber <= certificatesRequests.length);
        return uint(certificateStatus[serialNumber]);
    }

    function getCertificateStatus(
        string memory name
    ) public view returns (uint) {
        require(nameToSerialNumber[name] > 0, "No certificate for this name");
        return uint(certificateStatus[nameToSerialNumber[name] - 1]);
    }
}

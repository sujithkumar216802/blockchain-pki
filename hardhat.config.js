require("@nomicfoundation/hardhat-toolbox");

/** @type import('hardhat/config').HardhatUserConfig */
module.exports = {
  solidity: {
    compilers: [{
      version: "0.8.18",
      settings: {
        viaIR: true,
        optimizer: { enabled: true },
      },
    }]
  },
  defaultNetwork: "ganache",
  networks: {
    hardhat: {
      allowUnlimitedContractSize: true
    },
    ganache: {
      url: "http://172.19.176.1:7545",
      accounts: ['0x85ebffcaf3526084e30714a08f1160a1d93a8a09331107e5f84b8bf6257dc709', '0x97786e0688bb1c9234f2929040090cee0b0c23659236fdd36c2ee7e0de760d42', '0x5b185474e2f1811bfc8ae8fc81ab33d145270f2cc7131416ee446e06ad2f0811', '0x7894a1d38da01a7910f6d0e78408ea38cbdce1c55ef5c4e249280fa424778b03']
    }
  }
};

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
  networks: {
    hardhat: {
      allowUnlimitedContractSize: true
    }
    
  }
};

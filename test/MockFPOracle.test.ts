import { expect } from "chai";
import { Contract } from "ethers";
import { ethers } from "hardhat";

describe("MockFPOracle", function () {
  let fpOracle: Contract;
  let schnorrLib: Contract;
  let eotsVerifier: Contract;

  const chainId = 1;
  const fromBlock = 5;

  before(async function () {
    // Deploy MockFPOracle contract
    const FPOracle = await ethers.getContractFactory("MockFPOracle");
    fpOracle = await FPOracle.deploy();
    await fpOracle.deployed();

    // Deploy SchnorrLib library
    const SchnorrLib = await ethers.getContractFactory("SchnorrLib");
    schnorrLib = await SchnorrLib.deploy();
    await schnorrLib.deployed();

    // Deploy EOTSVerifier contract with SchnorrLib linked
    const EOTSVerifier = await ethers.getContractFactory("EOTSVerifier", {
      libraries: {
        SchnorrLib: schnorrLib.address,
      },
    });
    eotsVerifier = await EOTSVerifier.deploy(fpOracle.address);
    await eotsVerifier.deployed();
  });

  it("should set and get total voting power", async function () {
    const power = 100;

    // Set voting power for total voting power
    await fpOracle.setVotingPower(chainId, fromBlock, power);

    // Get voting power
    const result = await fpOracle.getVotingPower(chainId, fromBlock);

    expect(result).to.equal(power);
  });

  it("should set and get voting power for FP", async function () {
    const power = 100;

    // Set voting power with public key
    const pubKey = Buffer.from("0x123");
    await fpOracle.setVotingPowerFor(chainId, fromBlock, pubKey, power);

    // Get voting power
    const result = await fpOracle.getVotingPowerFor(chainId, fromBlock, pubKey);

    expect(result).to.equal(power);
  });
});

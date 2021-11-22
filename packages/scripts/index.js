const {
  genPrivateKey,
  genPublicKey,
  formatBabyJubJubPrivateKey,
  SNARK_FIELD_SIZE,
  genPrivateKeyHash
} = require("./utils/crypto.js");

// 智能合约部署地址
const {
  zkIdentityAddress
} = require("../zk-contracts/build/DeployedAddresses.json");

// 智能合约的ABI
const zkIdentityDef = require("../zk-contracts/build/ZkIdentity.json");

const { binarifyWitness, binarifyProvingKey } = require("./utils/binarify");

// snarkjs生成的两个密钥
const provingKey = require("../zk-circuits/build/provingKey.json");
const verifyingKey = require("../zk-circuits/build/verifyingKey.json");

const compiler = require("circom");
const { buildBn128 } = require("websnark");
const { Circuit, groth, bigInt } = require("snarkjs");
const {
  stringifyBigInts,
  unstringifyBigInts
} = require("snarkjs/src/stringifybigint");
const { ethers } = require("ethers");

// 连接ganache
const provider = new ethers.providers.JsonRpcProvider("http://localhost:7545");
const wallet = new ethers.Wallet(
  "0xe9eaced2ac0ea13e8e5ce37c6a9b3c9083407bc6511287cf96ed4d311c1e8003",
  provider
);
const zkIdentityContract = new ethers.Contract(
  zkIdentityAddress,
  zkIdentityDef.abi,
  wallet
);

// These are the key pairs specified in the smart contract (ZkIdentity.sol)
// 两个公钥
const validSk1 = bigInt(
  "5127263858703129043234609052997016034219110701251230596053007266606287227503"
);
const validSk2 = bigInt(
  "859505848622195548664064193769263253816895468776855574075525012843176328128"
);

//两个公钥对应的私钥
const validPub1 = genPublicKey(validSk1);
const validPub2 = genPublicKey(validSk2);

//生成两个无效公钥
const invalidSk1 = genPrivateKey();
const invalidSk2 = genPrivateKey();

//两个无效公钥的对应密钥
const invalidPub1 = genPublicKey(invalidSk1);
const invalidPub2 = genPublicKey(invalidSk2);

//验证过程
const generateProofAndSubmitToContract = async (sk, pks, option_id, vote_id) => {
  // 获取电路定义
  const circuitDef = await compiler(
    require.resolve("../zk-circuits/src/circuit.circom")
  );
  const circuit = new Circuit(circuitDef);

  const circuitInputs = {
    privateKey: formatBabyJubJubPrivateKey(sk),
    publicKeys: pks,
    privateKey_init: sk,
    privateKey_hash: genPrivateKeyHash(sk),
    optionid: option_id,
    optionid_public: option_id,
    voteid: vote_id,
    voteid_public: vote_id
  };

  // Calculate witness and public signals
  console.log("Generating witness....");
  const witness = circuit.calculateWitness(stringifyBigInts(circuitInputs));
  const publicSignals = witness.slice(
    1,
    circuit.nPubInputs + circuit.nOutputs + 1
  );

  // Websnark to generate proof
  const wasmBn128 = await buildBn128();
  const zkSnark = groth;

  console.log("Generating proof....");
  const witnessBin = binarifyWitness(witness);
  const provingKeyBin = binarifyProvingKey(provingKey);
  const proof = await wasmBn128.groth16GenProof(witnessBin, provingKeyBin);
  const isValid = zkSnark.isValid(
    unstringifyBigInts(verifyingKey),
    unstringifyBigInts(proof),
    unstringifyBigInts(publicSignals)
  );

  // Need to massage inputs to fit solidity format
  const solidityProof = {
    a: stringifyBigInts(proof.pi_a).slice(0, 2),
    b: stringifyBigInts(proof.pi_b)
      .map(x => x.reverse())
      .slice(0, 2),
    c: stringifyBigInts(proof.pi_c).slice(0, 2),
    inputs: publicSignals.map(x => x.mod(SNARK_FIELD_SIZE).toString())
  };
  console.log(`Passed local zk-snark verification: ${isValid}`);
  
  // Submit to smart contract
  await zkIdentityContract.isInGroup(
    solidityProof.a,
    solidityProof.b,
    solidityProof.c,
    solidityProof.inputs
  );

};

const generateProofAndSubmitToContract1 = async (sk, pks, option_id, vote_id) => {
  // 获取电路定义
  const circuitDef = await compiler(
    require.resolve("../zk-circuits/src/circuit.circom")
  );
  const circuit = new Circuit(circuitDef);

  const circuitInputs = {
    privateKey: formatBabyJubJubPrivateKey(sk),
    publicKeys: pks,
    privateKey_init: sk,
    privateKey_hash: genPrivateKeyHash(sk),
    optionid: option_id,
    optionid_public: option_id,
    voteid: vote_id,
    voteid_public: vote_id
  };

  // Calculate witness and public signals
  console.log("Generating witness....");
  const witness = circuit.calculateWitness(stringifyBigInts(circuitInputs));
  const publicSignals = witness.slice(
    1,
    circuit.nPubInputs + circuit.nOutputs + 1
  );

  // Websnark to generate proof
  const wasmBn128 = await buildBn128();
  const zkSnark = groth;

  console.log("Generating proof....");
  const witnessBin = binarifyWitness(witness);
  const provingKeyBin = binarifyProvingKey(provingKey);
  const proof = await wasmBn128.groth16GenProof(witnessBin, provingKeyBin);
  const isValid = zkSnark.isValid(
    unstringifyBigInts(verifyingKey),
    unstringifyBigInts(proof),
    unstringifyBigInts(publicSignals)
  );

  // Need to massage inputs to fit solidity format
  const solidityProof = {
    a: stringifyBigInts(proof.pi_a).slice(0, 2),
    b: stringifyBigInts(proof.pi_b)
      .map(x => x.reverse())
      .slice(0, 2),
    c: stringifyBigInts(proof.pi_c).slice(0, 2),
    inputs: publicSignals.map(x => x.mod(SNARK_FIELD_SIZE).toString())
  };
  console.log(`Passed local zk-snark verification: ${isValid}`);

  solidityProof.inputs[4] = 0;
  
  // Submit to smart contract
  await zkIdentityContract.isInGroup(
    solidityProof.a,
    solidityProof.b,
    solidityProof.c,
    solidityProof.inputs
  );

};

const create_vote = async (vote) => {
  await zkIdentityContract.create_vote(vote);
}

const find_vote = async (vote) => {
  const vote_id = await zkIdentityContract.return_vote_id(vote);
  return parseInt(vote_id);
}

const create_option = async (option, id) => {
  await zkIdentityContract.create_option(option, id);
}

const find_option = async (option, id) => {
  await zkIdentityContract.find_option(option, id);
  const vote_option = await zkIdentityContract.return_option();
  return parseInt(vote_option)
}

const find_result = async (option, id) => {
  await zkIdentityContract.find_option(option, id);
  const vote_result = await zkIdentityContract.find_result(id);
  return parseInt(vote_result);
}

const return_result = async (id) => {
  await zkIdentityContract.vote_result(id);
  const result = await zkIdentityContract.return_vote_result();
  console.log(result);
}

const create_cishu = async (id, count) => {
  await zkIdentityContract.votecishu(id, count);
}

const main = async () => {

  await create_vote('who is the s11 champion');
  var vote_id = await find_vote('who is the s11 champion');
  console.log(vote_id);

  await create_cishu(vote_id, 2);

  await create_option('RNG', vote_id);
  await create_option('IG', vote_id);
  await create_option('EDG', vote_id);

  var option_id = await find_option('EDG', vote_id);
  console.log(option_id);

  //await generateProofAndSubmitToContract(validSk1, [validPub1, validPub2], option_id, vote_id);
  await generateProofAndSubmitToContract(validSk2, [validPub1, validPub2], option_id, vote_id);
  await generateProofAndSubmitToContract1(validSk2, [validPub1, validPub2], option_id, vote_id);
  await generateProofAndSubmitToContract1(validSk2, [validPub1, validPub2], option_id, vote_id);

  var option_id = await find_option('IG', vote_id);
  console.log(option_id);

  await generateProofAndSubmitToContract(validSk1, [validPub1, validPub2], option_id, vote_id);
  await generateProofAndSubmitToContract(validSk1, [validPub1, validPub2], option_id, vote_id);
  await generateProofAndSubmitToContract1(validSk1, [validPub1, validPub2], option_id, vote_id);
  await generateProofAndSubmitToContract1(validSk1, [validPub1, validPub2], option_id, vote_id);

  await return_result(vote_id);

  console.log('MMMM');
  var t1 = await zkIdentityContract.test(0, 0);
  var t2 = await zkIdentityContract.test(1, 0);
  var t3 = await zkIdentityContract.test(2, 0);

  console.log(parseInt(t1));
  console.log(parseInt(t2));
  console.log(parseInt(t3));
  process.exit(0);

};

main();


// const main = async () => {

//   await create_vote('wenti');
//   await find_vote('wenti');

//   await create_option('Tom', 0);
//   await create_option('Sam', 0);
//   await create_option('John', 0);

//   await find_option('Sam', 0);

//   console.log("------------------------------------------------------");
//   console.log("Interacting with deployed zk-dapp....");
//   console.log("------------------------------------------------------");
//   console.log("");
//   console.log("------------------------------------------------------");

//   console.log(
//     "1. Supplying derived key pair that exists in the smart contract...."
//   );
//   await generateProofAndSubmitToContract(validSk1, [validPub1, validPub2], 1, 0);
//   console.log("------------------------------------------------------");
//   console.log("");

//   console.log("------------------------------------------------------");

//   console.log(
//     "2. Supplying derived key pair that _does_ _not_ exists in the smart contract...."
//   );
//   try {
//     await generateProofAndSubmitToContract(genPrivateKey(), [validPub1, validPub2], 1, 0);
//   } catch (e) {
//     console.log("(Expected behavior)");
//     console.log(`${e}`);
//   }
//   console.log("------------------------------------------------------");
//   console.log("");

//   console.log("------------------------------------------------------");
//   console.log("3. Supplying invalid public keys....");
//   try {
//     await generateProofAndSubmitToContract(invalidSk1, [invalidPub1, invalidPub2], 1, 0);
//   } catch (e) {
//     console.log("(Expected behavior)");
//     console.log(`${e}`);
//   }
//   console.log("------------------------------------------------------");
//   console.log("");
//   console.log("------------------------------------------------------");

//   console.log(
//     "4. Repeat supply derived key pair that exists in the smart contract...."
//   );
//   try {
//     await generateProofAndSubmitToContract(validSk1, [validPub1, validPub2], 1, 0);
//   } catch (e) {
//     console.log("(Expected behavior)");
//     console.log(`${e}`);
//   }
//   console.log("------------------------------------------------------");
//   console.log("");

//   console.log("------------------------------------------------------");

//   await return_result(0);

//   process.exit(0);
// };

// main();
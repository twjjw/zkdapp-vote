include "../node_modules/circomlib/circuits/bitify.circom";
include "../node_modules/circomlib/circuits/escalarmulfix.circom";
include "../node_modules/circomlib/circuits/comparators.circom";
include "../node_modules/circomlib/circuits/pedersen.circom";

template EncodePedersenPoint() {
    signal input x;
    signal input y;
    signal output out;

    var n = 256;

    // convert x to bits
    component xBits = Num2Bits(n);
    xBits.in <-- x;

    // convert y to bits
    component yBits = Num2Bits(n);
    yBits.in <-- y;

    // insert the first 248 bits of y
    component resultNum = Bits2Num(n);
    for (var i=0; i<256-8; i++) {
        resultNum.in[i] <-- yBits.out[i];
    }

    // insert the last 8 bits of x
    for (var j=256-8; j<n; j++) {
        resultNum.in[j] <-- xBits.out[j]
    }

    out <-- resultNum.out;
}

template PedersenHashSingle() {
    signal input in;
    signal output out[2];
    signal output encoded;

    component n2b = Num2Bits(256);
    n2b.in <== in;

    component pedersen = Pedersen(256);
    for (var m=0; m<256; m++) {
        pedersen.in[m] <-- n2b.out[m];
    }
    
    out[0] <== pedersen.out[0];
    out[1] <== pedersen.out[1];

    component encoder = EncodePedersenPoint();
    encoder.x <== pedersen.out[0];
    encoder.y <== pedersen.out[1];
    encoded <== encoder.out;
}

template PublicKey() {
  // Note: private key
  // Needs to be hashed, and then pruned before
  // supplying it to the circuit
  signal private input in;
  signal output out[2];

  component privBits = Num2Bits(253);
  privBits.in <== in;

  var BASE8 = [
    5299619240641551281634865583518297030282874472190772894086521144482721001553,
    16950150798460657717958625567821834550301663161624707787222815936182638968203
  ];

  component mulFix = EscalarMulFix(253, BASE8);
  for (var i = 0; i < 253; i++) {
    mulFix.e[i] <== privBits.out[i];
  }

  out[0] <== mulFix.out[0];
  out[1] <== mulFix.out[1];
}

template ZkIdentity(groupSize) {
  // Public Keys in the smart contract
  signal input publicKeys[groupSize][2];

  // Prover's private key
  signal private input privateKey;
  
  // test
  signal private input privateKey_init;
  signal input privateKey_hash;

  signal private input optionid;
  signal input optionid_public;

  signal private input voteid;
  signal input voteid_public;

  // Prover's derived public key
  component publicKey = PublicKey();
  publicKey.in <== privateKey;

  // Make sure that derivate public key
  // matches to at least one public key
  // in the smart contract to validate their
  // identity
  var sum = 0;
  component equals[groupSize][2];
  for (var i = 0; i < groupSize; i++) {
    equals[i][0] = IsEqual();
    equals[i][1] = IsEqual();

    equals[i][0].in[0] <== publicKeys[i][0];
    equals[i][0].in[1] <== publicKey.out[0];

    equals[i][1].in[0] <== publicKeys[i][1];
    equals[i][1].in[1] <== publicKey.out[1];

    sum += equals[i][0].out;
    sum += equals[i][1].out;
  }

  // Make sure that public keys matches one of the public
  // keys in the group
  sum === 2;
  
  component pedersen = PedersenHashSingle();
  pedersen.in <== privateKey_init;
  privateKey_hash === pedersen.encoded;

  optionid_public === optionid;

  voteid_public === voteid;
  
}

component main = ZkIdentity(2);


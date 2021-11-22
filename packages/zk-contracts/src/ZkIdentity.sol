pragma solidity 0.5.11;

import "zk-circuits/build/Verifier.sol";

contract ZkIdentity is Verifier {
    address public owner;
    uint256[2][2] public publicKeys;
    uint256[] public pkHash_list;
    uint flag;
    string fin;
    bool panduan;

    mapping (string => int) public vote;
    mapping (int => int) public vote_cishu;

    int vote_id = 0;
    mapping (int => bytes[]) public option;
    mapping (int => int[]) public result;
    mapping (int => uint256[]) public sk_hash;
    mapping (int => int[]) public sk_hash_cishu;

    constructor() public {
        owner = msg.sender;
        publicKeys = [
            [
                11588997684490517626294634429607198421449322964619894214090255452938985192043,
                15263799208273363060537485776371352256460743310329028590780329826273136298011
            ],
            [
                3554016859368109379302439886604355056694273932204896584100714954675075151666,
                17802713187051641282792755605644920157679664448965917618898436110214540390950
            ]
        ];
    }

    function create_vote(string memory vote_problem) public {
        vote[vote_problem] = vote_id;
        vote_id++;
    }

    function return_vote_id(string memory vote_problem) public view returns (int) {
        return vote[vote_problem];
    }

    function string2Bytes(string memory option) public returns (bytes memory){
        return bytes(option);
    }

    function Bytes2string(bytes memory option) public returns (string memory) {
        return string(option);
    }

    function create_option(string memory vote_option, int id) public {
        bytes memory mid = string2Bytes(vote_option);
        option[id].push(mid);
        result[id].push(0);
    }

    function find_option(string memory vote_option, int id) public {
        for(uint i = 0; i < option[id].length; i++){
            string memory mid = Bytes2string(option[id][i]);
            if (keccak256(abi.encodePacked(mid)) == keccak256(abi.encodePacked(vote_option))) {
                flag = i;
                break;
            }
        }
    }

    function find_result(int id) public view returns (int) {
        return result[id][flag];
    }

    function return_option() public view returns (uint) {
        return flag;
    }

    function vote_count(uint option_id, uint id) private {
        int n = int(id);
        result[n][option_id]++;
    }

    function vote_result(int id) public {
        int p = 0;
        uint q = 0;
        for(uint i = 0; i < result[id].length; i++) {
            if(result[id][i] > p){
                p = result[id][i];
                q = i;
            }
        }
        fin = Bytes2string(option[id][q]);
    }

    function return_vote_result() public view returns (string memory) {
        return fin;
    }

    function isInGroup(
        uint256[2] memory a,
        uint256[2][2] memory b,
        uint256[2] memory c,
        uint256[7] memory input // public inputs
    ) public {
        if (
            input[0] != publicKeys[0][0] &&
            input[1] != publicKeys[0][1] &&
            input[2] != publicKeys[1][0] &&
            input[3] != publicKeys[1][1]
        ) {
            revert("Supplied public keys do not match contracts");
        }

        uint256 biaozhi = 100;
        int cishu;
        int sss = 0;
        if (verifyProof(a, b, c, input)) {
            int p = int(input[6]);
            cishu = vote_cishu[p];
            for (uint i = 0; i < sk_hash[p].length; i++) {
                if (sk_hash[p][i] == input[4]) {
                    biaozhi = i;
                }
            }
            if (biaozhi != 100) {
                if (sk_hash_cishu[p][biaozhi] < cishu){
                    sss = 1;
                }
            }
            if (biaozhi == 100 || sss == 1) {
                vote_count(input[5], input[6]);
                sk_hash[p].push(input[4]);
                sk_hash_cishu[p].push(0);
            }
        }

    }

    function test(uint option_id, int id) public view returns (int) {
        return result[id][option_id];
    }

    function votecishu(int vote_id, int cishu) public {
        vote_cishu[vote_id] = cishu;
    }
}

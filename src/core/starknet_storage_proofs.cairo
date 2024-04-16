use core::result::ResultTrait;
use alexandria_merkle_tree::storage_proof;
use alexandria_merkle_tree::storage_proof::{
    ContractData, ContractStateProof, TrieNode, BinaryNode, EdgeNode, node_hash, pow,
    pedersen_hash_4, poseidon_hash
};
use starknet::syscalls::get_block_hash_syscall;
use pedersen::PedersenTrait;
use hash::HashStateTrait;

// After 0.12
#[derive(Drop)]
struct StarknetBlockHeader {
    block_number: felt252,
    global_state_root: felt252,
    sequencer_address: felt252,
    block_timestamp: felt252,
    parent_block_hash: felt252,
    transaction_count: felt252,
    transaction_commitment: felt252,
    event_count: felt252,
    event_commitment: felt252,
}

// Expected state commitment <=> global state root
fn verify_single_storage_proof(
    contract_address: felt252,
    storage_address: felt252,
    proof: ContractStateProof,
    block_header: @StarknetBlockHeader,
) -> felt252 {
    let res = storage_proof::verify(
        expected_state_commitment: *block_header.global_state_root,
        contract_address: contract_address,
        storage_address: storage_address,
        proof: proof
    );
    return res;
}


fn get_block_hash(block_number: u64) -> felt252 {
    let block_hash = get_block_hash_syscall(block_number).unwrap();
    return block_hash;
}


#[generate_trait]
impl StarknetBlockHeaderImpl of StarknetBlockHeaderTrait {
    fn hash(self: @StarknetBlockHeader) -> felt252 {
        // compute_hash_on_elements([block_number, global_state_root, sequencer_address, block_timestamp, transaction_count, transaction_commitment, event_count, event_commitment, 0, 0, parent_block_hash])
        PedersenTrait::new(0) // State init
            .update(*self.block_number)
            .update(*self.global_state_root)
            .update(*self.sequencer_address)
            .update(*self.block_timestamp)
            .update(*self.transaction_count)
            .update(*self.transaction_commitment)
            .update(*self.event_count)
            .update(*self.event_commitment)
            .update(0)
            .update(0)
            .update(*self.parent_block_hash)
            .update(11) // 11 elements
            .finalize()
    }
}
#[starknet::interface]
trait IStarknetSP<TContractState> {
    fn verify_starknet_storage_proof(self: @TContractState) -> felt252;
}

// @notice Contract responsible for storing all the block hashes
// @dev The contract keeps track of multiple MMRs (refered to as branches), each with a different id
// // @dev The contract also keeps track of historical roots and corresponding sizes of every MMR, 
// #[starknet::contract]
// mod StarknetSP {
//     use starknet::{ContractAddress, get_caller_address};

//     #[storage]
//     struct Storage {
//         void: felt252
//     }

//     #[event]
//     #[derive(Drop, starknet::Event)]
//     enum Event {
//         HashReceived: HashReceived,
//     }

//     #[derive(Drop, starknet::Event)]
//     struct HashReceived {
//         block_number: u256,
//         parent_hash: u256,
//     }
//     #[constructor]
//     fn constructor(ref self: ContractState) {
//         self.void.write(0);
//     }

//     #[abi(embed_v0)]
//     impl StarknetSP of super::IStarknetSP<ContractState> {
//         // @inheritdoc IHeadersStore
//         fn verify_starknet_storage_proof(self: @ContractState) -> felt252 {
//             self.void.read()
//         }

// }

#[cfg(test)]
mod tests {
    use pedersen::PedersenTrait;
    use hash::HashStateTrait;
    use super::{get_block_hash, StarknetBlockHeader};
    use super::{ContractStateProof, ContractData, TrieNode, BinaryNode, EdgeNode};
    use super::verify_single_storage_proof;
    use super::StarknetBlockHeaderTrait;
    #[test]
    fn test_snsp_compute_hash_on_elements() {
        let x = PedersenTrait::new(0).update(1).update(0).update(0).update(3).update(4).finalize();
        assert!(
            x == 2190981037802520456428249848112124556068583141656717007858145314836616260514,
            "wrong compute_hash_on_elements([1, 0, 0, 3]) result"
        );
    }
    #[test]
    fn test_snsp_block_hash() {
        // Sepolia block 56399
        let block_hash_56399: felt252 =
            2164192536789366427034857826628165510214683759353778181510131152009496439065;
        let block_56399 = StarknetBlockHeader {
            block_number: 56399,
            global_state_root: 0x3f9310de4b831d181ddcb131ea9911cef1198e51d3035c876113faef432a654,
            sequencer_address: 0x1176a1bd84444c89232ec27754698e5d2e7e1a7f1539f12027f28b23ec9f3d8,
            block_timestamp: 0x660e6460,
            transaction_count: 0x24,
            transaction_commitment: 0x135c26bd5d840f205ce30823b375bb87d00205af64b894c2b6ba5ace95815b6,
            event_count: 0x75,
            event_commitment: 0x3707326e40b0d213c26e84b0d7950e12dbf2edd628f9a9433213025b9bc912,
            parent_block_hash: 0x26641f3ebf60add28e933d72b75594fed8e4d230a2aa841de1d3bea9cc6b839
        };
        assert_eq!((@block_56399).hash(), block_hash_56399);
    }
    #[test]
    fn test_snsp_storage_proof() {
        // Sepolia block 56400
        let block_hash_56400: felt252 =
            825158994069845277154461826238845226800238833810145968707295728754339672853;
        // calldata 
        let block_56400 = StarknetBlockHeader {
            block_number: 0xdc50,
            global_state_root: 0x598cf91d9a3a7176d01926e8442b8bd83299168f723cb2d52080e895400d9a1,
            sequencer_address: 0x1176a1bd84444c89232ec27754698e5d2e7e1a7f1539f12027f28b23ec9f3d8,
            block_timestamp: 0x660e655e,
            transaction_count: 0x29,
            transaction_commitment: 0xf3a486166758b3e5772f3b55f1947f116505e2f1f5e7dc9864146a31902a78,
            event_count: 0x73,
            event_commitment: 0x37b168a49a58a42b3e549b24a56c57b3950d429494ef31f6fc9288586f853ec,
            parent_block_hash: 0x4c8e3baaff380d383dcb450df3b1161befa295a9973abe6e1f86a959bf52919
        };
        assert_eq!((@block_56400).hash(), block_hash_56400);

        let contract_address: felt252 =
            0x017E2D0662675DD83B4B58A0A659EAFA131FDD01FA6DABD5002D8815DD2D17A5;

        let csp: ContractStateProof = ContractStateProof {
            class_commitment: 1421983491458550120027272653440570462678362993783969812897487481094938412115,
            contract_proof: array![
                TrieNode::Binary(
                    BinaryNode {
                        left: 2661103503950959655886857804092400771604073933832646041293817345064968895641,
                        right: 584277427270843214375388741180003426347483767959313443714981369988920532112
                    }
                ),
                TrieNode::Binary(
                    BinaryNode {
                        left: 1477206976496124141994753937804996767139746894744194961680636145205098611667,
                        right: 3168051189937013833985620891113145087408884263974272082047842321849340128355
                    }
                ),
                TrieNode::Binary(
                    BinaryNode {
                        left: 2919413365329319931856362390626855868004550446000993158533936247707313861303,
                        right: 1003444757227095524970518342745716982899615440715453207351777690059155213058
                    }
                ),
                TrieNode::Binary(
                    BinaryNode {
                        left: 1757992302753897915493746161931908984426198143819579713663689186254723203298,
                        right: 1078732932529308295128679066728561000617415024525406722036943093383096967660
                    }
                ),
                TrieNode::Binary(
                    BinaryNode {
                        left: 2372309230587369321766586215571293513723614138443783942215428848292019316315,
                        right: 2267125599971060688968437506471333332579312868184801395952598317206078560909
                    }
                ),
                TrieNode::Binary(
                    BinaryNode {
                        left: 599041694925524023195142795074901728803524648352754641738564516891924292579,
                        right: 2969544917331360894937397788256743384072458446248721848610363468209533582517
                    }
                ),
                TrieNode::Binary(
                    BinaryNode {
                        left: 3568770396690156972900393773709188336763445861909108308839642788513268720192,
                        right: 2869223049565402829950952566852157899954655133447499326980799351276068633271
                    }
                ),
                TrieNode::Binary(
                    BinaryNode {
                        left: 3340900499031806278685528846051436583231646450129196140191480421675250581618,
                        right: 91646903722138224113082359678974378990238109101398426125445064100141451981
                    }
                ),
                TrieNode::Binary(
                    BinaryNode {
                        left: 1155750946301306555902838784537705938383979078995103279387853281512464191177,
                        right: 2526036635413210967357454239998940713422112566207011857619392769095951830372
                    }
                ),
                TrieNode::Binary(
                    BinaryNode {
                        left: 2946142426170399138537381151983842224698407230867699187203926683932215493205,
                        right: 1073701200173331669424937605706285156927561355693752533579828217045540713274
                    }
                ),
                TrieNode::Binary(
                    BinaryNode {
                        left: 2947331851784164135171112953312764613604157338700197171831834580100811020457,
                        right: 404113537255705621550809476400346104879678800147102436077694610503275820451
                    }
                ),
                TrieNode::Binary(
                    BinaryNode {
                        left: 2005084121153711516249521748795506700941009720521932848497205564523966022214,
                        right: 1661245195605260737530394120231758766275632667399255525048558587911530258649
                    }
                ),
                TrieNode::Binary(
                    BinaryNode {
                        left: 38132809618552923086338726237347323778848969495509197399191385366302795481,
                        right: 2567317189706000069024641567258069342514131247444625590014717784563962960987
                    }
                ),
                TrieNode::Binary(
                    BinaryNode {
                        left: 404379873140998751171921811702176352540092873544949774081750077966078309171,
                        right: 1463942402782693973336180756055839732847728257745309899836302045812628144405
                    }
                ),
                TrieNode::Binary(
                    BinaryNode {
                        left: 1409851947109724468801892353950037259256541718723021023440859981201878492565,
                        right: 268188145205620947666863213112018479113986282392653841743702202408234496431
                    }
                ),
                TrieNode::Binary(
                    BinaryNode {
                        left: 2422773448256116425438280986834711821825769538307994116998721479620111129429,
                        right: 434664675535838524960082444928163605300359665875728797731875167174552830062
                    }
                ),
                TrieNode::Edge(
                    EdgeNode {
                        child: 3391474284457069376342737191283093093060418594138081180253570471500038251163,
                        path: 34680854541084138384746305582871190293255928288364696201483342633047973,
                        length: 235
                    }
                ),
            ],
            contract_data: ContractData {
                class_hash: 854040042974349403804076041510219612777577847638682743542093770150884448108,
                nonce: 0,
                contract_state_hash_version: 0,
                storage_proof: array![
                    TrieNode::Binary(
                        BinaryNode {
                            left: 286814580954438953652789027217042980566530324746975211316396249060034312394,
                            right: 403028085264434463331791313843119867796379333415957132455339500305119455247
                        }
                    ),
                    TrieNode::Binary(
                        BinaryNode {
                            left: 3526971112447807949875832541609385105567020034420772359472063532991162319091,
                            right: 426989591449116434709307516099215167414525240904029710533253135529318671420
                        }
                    ),
                    TrieNode::Binary(
                        BinaryNode {
                            left: 2135846475486066363054009917859622543055751452139138885784469341891333409709,
                            right: 1175137542582516138740621979561236498012018093636093760155860381427950932165
                        }
                    ),
                    TrieNode::Binary(
                        BinaryNode {
                            left: 514773575696029908110914288732559925889618501766824076683729040222771341554,
                            right: 198121671998432816826353034974792851384698311164811211146625127459894414076
                        }
                    ),
                    TrieNode::Edge(
                        EdgeNode {
                            child: 18,
                            path: 134830404806214277570220174593674215737759987247891306080029841794115377321,
                            length: 247
                        }
                    ),
                ]
            }
        };
        // sn_keccak("decimals")
        let storage_address = 0x004c4fb1ab068f6039d5780c68dd0fa2f8742cceb3426d19667778ca7f3518a9;
        let res = verify_single_storage_proof(contract_address, storage_address, csp, @block_56400);
        assert!(res == 18);
    }
}

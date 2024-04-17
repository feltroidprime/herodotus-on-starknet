// use core::result::ResultTrait;
use alexandria_merkle_tree::storage_proof;
use alexandria_merkle_tree::storage_proof::{
    ContractStateProof, ContractData, TrieNode, BinaryNode, EdgeNode
};
// use pedersen::PedersenTrait;
// use hash::HashStateTrait;
use cairo_lib::data_structures::starknet_block::{StarknetBlockHeader, StarknetBlockHeaderImpl};


#[starknet::interface]
trait IStarknetSP<TContractState> {
    fn verify_starknet_storage_proof(
        self: @TContractState,
        block_header: StarknetBlockHeader,
        storage_proof: ContractStateProof,
        storage_address: felt252,
        contract_address: felt252
    ) -> felt252;
    fn get_block_hash(self: @TContractState, block_number: u64) -> felt252;
}


#[starknet::contract]
mod StarknetSP {
    use core::result::ResultTrait;
    use core::traits::TryInto;
    use starknet::{ContractAddress, get_caller_address};
    use cairo_lib::data_structures::starknet_block::{StarknetBlockHeader, StarknetBlockHeaderImpl};
    use starknet::syscalls::get_block_hash_syscall;
    use alexandria_merkle_tree::storage_proof::{
        ContractStateProof, ContractData, TrieNode, BinaryNode, EdgeNode
    };
    use alexandria_merkle_tree::storage_proof;
    #[storage]
    struct Storage {
        void: felt252
    }

    #[constructor]
    fn constructor(ref self: ContractState) {
        self.void.write(0);
    }

    #[abi(embed_v0)]
    impl StarknetSP of super::IStarknetSP<ContractState> {
        fn verify_starknet_storage_proof(
            self: @ContractState,
            block_header: StarknetBlockHeader,
            storage_proof: ContractStateProof,
            storage_address: felt252,
            contract_address: felt252
        ) -> felt252 {
            // Get corresponding block hash for the given block header
            let expected_block_hash = get_block_hash_syscall(
                block_header.block_number.try_into().unwrap()
            )
                .unwrap();
            // Prove provided block header fields are correct by comparing block hashes
            assert!(expected_block_hash == (@block_header).hash());

            // verify provided storage proof for the given contract address and storage address
            let res = storage_proof::verify(
                expected_state_commitment: block_header.global_state_root,
                contract_address: contract_address,
                storage_address: storage_address,
                proof: storage_proof
            );
            // return storage value 
            return res;
        }
        fn get_block_hash(self: @ContractState, block_number: u64) -> felt252 {
            return get_block_hash_syscall(block_number).unwrap();
        }
    }
}

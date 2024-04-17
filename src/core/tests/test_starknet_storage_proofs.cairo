use herodotus_eth_starknet::core::starknet_storage_proofs::IStarknetSPDispatcherTrait;
use snforge_std::{declare, ContractClassTrait};
use herodotus_eth_starknet::core::starknet_storage_proofs::IStarknetSPDispatcher;

#[test]
fn test_storage_proof_verification() {
    let contract = declare("StarknetSP");
    let contract_address = contract.deploy(@ArrayTrait::new()).unwrap();
    let dispatcher = IStarknetSPDispatcher { contract_address };
    let res = dispatcher.get_block_hash(56400);
    println!("res: {:?}", res);
}


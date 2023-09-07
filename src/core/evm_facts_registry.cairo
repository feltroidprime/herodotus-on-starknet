use starknet::ContractAddress;
use cairo_lib::data_structures::mmr::proof::Proof;
use cairo_lib::data_structures::mmr::peaks::Peaks;
use cairo_lib::utils::types::words64::Words64;

#[derive(Drop, Serde)]
enum AccountField {
    StorageHash: (),
    CodeHash: (),
    Balance: (),
    Nonce: ()
}

#[starknet::interface]
trait IEVMFactsRegistry<TContractState> {
    fn get_headers_store(self: @TContractState) -> ContractAddress;

    fn get_account_field(
        self: @TContractState, account: felt252, block: u256, field: AccountField
    ) -> u256;
    fn get_slot_value(self: @TContractState, account: felt252, block: u256, slot: u256) -> u256;

    fn get_account(
        self: @TContractState,
        fields: Span<AccountField>,
        block_header_rlp: Words64,
        account: felt252,
        mpt_proof: Span<Words64>,
        mmr_index: usize,
        mmr_peaks: Peaks,
        mmr_proof: Proof,
        mmr_id: usize,
    ) -> Span<u256>;
    fn get_storage(
        self: @TContractState,
        block: u256,
        account: felt252,
        slot: u256,
        slot_len: usize,
        mpt_proof: Span<Words64>
    ) -> u256;

    fn prove_account(
        ref self: TContractState,
        fields: Span<AccountField>,
        block_header_rlp: Words64,
        account: felt252,
        mpt_proof: Span<Words64>,
        mmr_index: usize,
        mmr_peaks: Peaks,
        mmr_proof: Proof,
        mmr_id: usize,
    );
    fn prove_storage(
        ref self: TContractState,
        block: u256,
        account: felt252,
        slot: u256,
        slot_len: usize,
        mpt_proof: Span<Words64>
    );
}

#[starknet::contract]
mod EVMFactsRegistry {
    use starknet::ContractAddress;
    use super::AccountField;
    use cairo_lib::data_structures::mmr::proof::Proof;
    use cairo_lib::data_structures::mmr::peaks::Peaks;
    use cairo_lib::hashing::poseidon::PoseidonHasherWords64;
    use cairo_lib::data_structures::eth_mpt::MPTTrait;
    use cairo_lib::encoding::rlp::{RLPItem, rlp_decode};
    use cairo_lib::utils::types::words64::{Words64, Words64TryIntoU256LE};
    use herodotus_eth_starknet::core::headers_store::{
        IHeadersStoreDispatcherTrait, IHeadersStoreDispatcher
    };

    #[storage]
    struct Storage {
        headers_store: ContractAddress,
        // Update to EthAddress when supported
        // (account_address, block_number) => value
        storage_hash: LegacyMap::<(felt252, u256), u256>,
        code_hash: LegacyMap::<(felt252, u256), u256>,
        balance: LegacyMap::<(felt252, u256), u256>,
        nonce: LegacyMap::<(felt252, u256), u256>,
        // (account_address, block_number, slot) => value
        slot_values: LegacyMap::<(felt252, u256, u256), u256>
    }

    #[event]
    #[derive(Drop, starknet::Event)]
    enum Event {
        AccountProven: AccountProven,
        StorageProven: StorageProven
    }

    #[derive(Drop, starknet::Event)]
    struct AccountProven {
        account: felt252,
        block: u256,
        fields: Span<AccountField>
    }

    #[derive(Drop, starknet::Event)]
    struct StorageProven {
        account: felt252,
        block: u256,
        slot: u256,
        value: u256
    }

    #[constructor]
    fn constructor(ref self: ContractState, headers_store: ContractAddress) {
        self.headers_store.write(headers_store);
    }

    #[external(v0)]
    impl EVMFactsRegistry of super::IEVMFactsRegistry<ContractState> {
        fn get_headers_store(self: @ContractState) -> ContractAddress {
            self.headers_store.read()
        }

        fn get_account_field(
            self: @ContractState, account: felt252, block: u256, field: AccountField
        ) -> u256 {
            match field {
                AccountField::StorageHash(_) => self.storage_hash.read((account, block)),
                AccountField::CodeHash(_) => self.code_hash.read((account, block)),
                AccountField::Balance(_) => self.balance.read((account, block)),
                AccountField::Nonce(_) => self.nonce.read((account, block))
            }
        }

        fn get_slot_value(self: @ContractState, account: felt252, block: u256, slot: u256) -> u256 {
            self.slot_values.read((account, block, slot))
        }

        fn get_account(
            self: @ContractState,
            fields: Span<AccountField>,
            block_header_rlp: Words64,
            account: felt252,
            mpt_proof: Span<Words64>,
            mmr_index: usize,
            mmr_peaks: Peaks,
            mmr_proof: Proof,
            mmr_id: usize,
        ) -> Span<u256> {
            let (_, fields) = InternalFunctions::get_account(
                self,
                fields,
                block_header_rlp,
                account,
                mpt_proof,
                mmr_index,
                mmr_peaks,
                mmr_proof,
                mmr_id
            );

            fields
        }

        fn get_storage(
            self: @ContractState,
            block: u256,
            account: felt252,
            slot: u256,
            slot_len: usize,
            mpt_proof: Span<Words64>
        ) -> u256 {
            let storage_hash = self.storage_hash.read((account, block));
            assert(storage_hash != Zeroable::zero(), 'Storage hash not proven');

            let mpt = MPTTrait::new(storage_hash);
            // TODO error handling
            let value = mpt.verify(slot, slot_len, mpt_proof).unwrap();

            value.try_into().unwrap()
        }

        fn prove_account(
            ref self: ContractState,
            fields: Span<AccountField>,
            block_header_rlp: Words64,
            account: felt252,
            mpt_proof: Span<Words64>,
            mmr_index: usize,
            mmr_peaks: Peaks,
            mmr_proof: Proof,
            mmr_id: usize,
        ) {
            let (block, field_values) = InternalFunctions::get_account(
                @self,
                fields,
                block_header_rlp,
                account,
                mpt_proof,
                mmr_index,
                mmr_peaks,
                mmr_proof,
                mmr_id
            );

            let mut i: usize = 0;
            loop {
                if i == field_values.len() {
                    break ();
                }

                let field = fields.at(i);
                let value = *field_values.at(i);

                match field {
                    AccountField::StorageHash(_) => {
                        self.storage_hash.write((account, block), value);
                    },
                    AccountField::CodeHash(_) => {
                        self.code_hash.write((account, block), value);
                    },
                    AccountField::Balance(_) => {
                        self.balance.write((account, block), value);
                    },
                    AccountField::Nonce(_) => {
                        self.nonce.write((account, block), value);
                    }
                };

                i += 1;
            };

            self.emit(Event::AccountProven(AccountProven { account, block, fields }));
        }

        fn prove_storage(
            ref self: ContractState,
            block: u256,
            account: felt252,
            slot: u256,
            slot_len: usize,
            mpt_proof: Span<Words64>
        ) {
            let value = EVMFactsRegistry::get_storage(
                @self, block, account, slot, slot_len, mpt_proof
            );
            self.slot_values.write((account, block, slot), value);

            self.emit(Event::StorageProven(StorageProven { account, block, slot, value: value }));
        }
    }

    #[generate_trait]
    impl InternalFunctions of InternalFunctionsTrait {
        // returns (block_number, account_fields)
        fn get_account(
            self: @ContractState,
            fields: Span<AccountField>,
            block_header_rlp: Words64,
            account: felt252,
            mpt_proof: Span<Words64>,
            mmr_index: usize,
            mmr_peaks: Peaks,
            mmr_proof: Proof,
            mmr_id: usize,
        ) -> (u256, Span<u256>) {
            let blockhash = PoseidonHasherWords64::hash_words64(block_header_rlp);

            let contract_address = self.headers_store.read();
            let mmr_inclusion = IHeadersStoreDispatcher {
                contract_address
            }.verify_mmr_inclusion(mmr_index, blockhash, mmr_peaks, mmr_proof, mmr_id);
            assert(mmr_inclusion, 'MMR inclusion not proven');

            let (decoded_rlp, _) = rlp_decode(block_header_rlp).unwrap();
            let mut state_root: u256 = 0;
            let mut block_number: u256 = 0;
            match decoded_rlp {
                RLPItem::Bytes(_) => panic_with_felt252('Invalid header rlp'),
                RLPItem::List(l) => {
                    state_root = (*l.at(3)).try_into().unwrap();
                    block_number = (*l.at(8)).try_into().unwrap();
                },
            };

            let mpt = MPTTrait::new(state_root);
            // TODO error handling
            let rlp_account = mpt.verify(account.into(), 32, mpt_proof).unwrap();

            let (decoded_account, _) = rlp_decode(rlp_account).unwrap();
            let mut account_fields = ArrayTrait::new();
            match decoded_account {
                RLPItem::Bytes(_) => panic_with_felt252('Invalid account rlp'),
                RLPItem::List(l) => {
                    let mut i: usize = 0;
                    loop {
                        if i == fields.len() {
                            break ();
                        }

                        let field = fields.at(i);
                        match field {
                            AccountField::StorageHash(_) => {
                                let storage_hash = (*l.at(2)).try_into().unwrap();
                                account_fields.append(storage_hash);
                            },
                            AccountField::CodeHash(_) => {
                                let code_hash = (*l.at(3)).try_into().unwrap();
                                account_fields.append(code_hash);
                            },
                            AccountField::Balance(_) => {
                                let balance = (*l.at(0)).try_into().unwrap();
                                account_fields.append(balance);
                            },
                            AccountField::Nonce(_) => {
                                let nonce = (*l.at(1)).try_into().unwrap();
                                account_fields.append(nonce);
                            },
                        };

                        i += 1;
                    };
                },
            };

            (block_number, account_fields.span())
        }
    }
}

use serde::{Deserialize, Serialize};

use ave_contract_sdk as sdk;

#[derive(Serialize, Deserialize, Clone)]
struct State {}

#[derive(Serialize, Deserialize)]
struct Event {}

#[unsafe(no_mangle)]
pub unsafe fn main_function(
    state_ptr: i32,
    init_state_ptr: i32,
    event_ptr: i32,
    is_owner: i32,
) -> u32 {
    sdk::execute_contract(
        state_ptr,
        init_state_ptr,
        event_ptr,
        is_owner,
        contract_logic,
    )
}

#[unsafe(no_mangle)]
pub unsafe fn init_check_function(state_ptr: i32) -> u32 {
    sdk::check_init_data(state_ptr, init_logic)
}

fn init_logic(_state: &State, result: &mut sdk::ContractInitCheck) {
    result.success = true;
}

fn contract_logic(
    _context: &sdk::Context<Event>,
    result: &mut sdk::ContractResult<State>,
) {
    result.success = true;
}

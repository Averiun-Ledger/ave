use serde::{Serialize, Deserialize};
use ave_contract_sdk as sdk;

/// Define the state of the contract. 
#[derive(Serialize, Deserialize, Clone)]
struct State {
  pub one: u32,
  pub two: u32,
  pub three: u32
}

#[derive(Serialize, Deserialize)]
enum StateEvent {
  ModOne { data: u32 },
  ModTwo { data: u32 },
  ModThree { data: u32 },
  ModAll { one: u32, two: u32, three: u32 }
}

#[unsafe(no_mangle)]
pub unsafe fn main_function(state_ptr: i32, init_state_ptr: i32, event_ptr: i32, is_owner: i32) -> u32 {
  sdk::execute_contract(state_ptr, init_state_ptr, event_ptr, is_owner, contract_logic)
}

#[unsafe(no_mangle)]
pub unsafe fn init_check_function(state_ptr: i32) -> u32 {
  sdk::check_init_data(state_ptr, init_logic)
}

fn init_logic(
  _state: &State,
  contract_result: &mut sdk::ContractInitCheck,
) {
  contract_result.success = true;
}

fn contract_logic(
  context: &sdk::Context<StateEvent>,
  contract_result: &mut sdk::ContractResult<State>,
) {
  let state = &mut contract_result.state;
  match context.event {
      StateEvent::ModOne { data } => {
        state.one = data;
      },
      StateEvent::ModTwo { data } => {
        state.two = data;
      },
      StateEvent::ModThree { data } => {
        if data == 50 {
          contract_result.error = "Can not change three value, 50 is a invalid value".to_owned();
          return
        }
        
        state.three = data;
      },
      StateEvent::ModAll { one, two, three } => {
        state.one = one;
        state.two = two;
        state.three = three;
      }
  }
  contract_result.success = true;
}
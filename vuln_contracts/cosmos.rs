use cosmwasm_std::{env, IbcMsg, StdResult};

// Vulnerability: Insecure Randomness
pub fn random_number() -> u64 {
    env::random() % 100
}

// Vulnerability: Unchecked Math
pub fn add_unchecked(a: u64, b: u64) -> u64 {
    a + b
}

// Vulnerability: Unprotected IBC Call
pub fn unprotected_ibc_call() -> StdResult<()> {
    IbcMsg::send_message("some_external_chain")
}

// Vulnerability: Reentrancy
pub fn reentrancy_example() {
    call_contract();
    self.state = "Updated state after external call";
}
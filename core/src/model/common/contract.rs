use std::collections::HashMap;

use wasmtime::{Caller, Config, Engine, Linker};

use crate::Error;
use tracing::error;

const TARGET_CONTRACT: &str = "Ave-Model-Contract";


#[derive(Debug, Default)]
pub struct MemoryManager {
    memory: Vec<u8>,
    map: HashMap<usize, usize>,
}

// Security limits to prevent memory exhaustion attacks
const MAX_TOTAL_MEMORY: usize = 5_000_000; // 5MB total memory limit (for production execution)
const MAX_SINGLE_ALLOC: usize = 2_000_000; // 2MB single allocation limit (for production execution)

// Fuel limits for contract execution
// Production limit: 10M operations (~100ms execution, suitable for 1000s of concurrent evaluations)
pub const MAX_FUEL: u64 = 10_000_000;
// Compilation/validation limit: 50M operations (contracts need more fuel during init)
pub const MAX_FUEL_COMPILATION: u64 = 50_000_000;

impl MemoryManager {
    pub fn alloc(&mut self, len: usize) -> Result<usize, Error> {
        // Security check: prevent excessive single allocations
        if len > MAX_SINGLE_ALLOC {
            return Err(Error::Runner(format!(
                "Allocation too large: {} bytes exceeds maximum of {} bytes",
                len, MAX_SINGLE_ALLOC
            )));
        }

        let current_len = self.memory.len();

        // Security check: prevent total memory exhaustion
        let new_len = current_len.checked_add(len).ok_or_else(|| {
            Error::Runner("Memory allocation would overflow".to_owned())
        })?;

        if new_len > MAX_TOTAL_MEMORY {
            return Err(Error::Runner(format!(
                "Total memory limit exceeded: {} bytes exceeds maximum of {} bytes",
                new_len, MAX_TOTAL_MEMORY
            )));
        }

        self.memory.resize(new_len, 0);
        self.map.insert(current_len, len);
        Ok(current_len)
    }

    pub fn write_byte(
        &mut self,
        start_ptr: usize,
        offset: usize,
        data: u8,
    ) -> Result<(), Error> {
        // Security check: validate pointer exists in allocation map
        let len = self.map.get(&start_ptr).ok_or_else(|| {
            Error::Runner(format!("Invalid write pointer: {}", start_ptr))
        })?;

        // Security check: validate write is within bounds
        if offset >= *len {
            return Err(Error::Runner(format!(
                "Write out of bounds: offset {} >= allocation size {}",
                offset, len
            )));
        }

        self.memory[start_ptr + offset] = data;
        Ok(())
    }

    pub fn read_byte(&self, ptr: usize) -> u8 {
        self.memory[ptr]
    }

    pub fn read_data(&self, ptr: usize) -> Result<&[u8], Error> {
        let len = self
            .map
            .get(&ptr)
            .ok_or(Error::Runner("Invalid pointer provided".to_owned()))?;
        Ok(&self.memory[ptr..ptr + len])
    }

    pub fn get_pointer_len(&self, ptr: usize) -> isize {
        let Some(result) = self.map.get(&ptr) else {
            return -1;
        };
        *result as isize
    }

    pub fn add_data_raw(&mut self, bytes: &[u8]) -> Result<usize, Error> {
        let ptr = self.alloc(bytes.len())?;
        for (index, byte) in bytes.iter().enumerate() {
            self.memory[ptr + index] = *byte;
        }
        Ok(ptr)
    }
}


/// Creates a secure Wasmtime configuration with resource limits.
/// This configuration is shared between contract compilation and execution
/// to ensure consistency.
pub fn create_secure_wasmtime_config() -> Config {
    let mut config = Config::default();

    // Enable fuel metering for gas-like execution limits
    config.consume_fuel(true);

    // Set maximum WASM stack size to 1MB to prevent stack overflow
    config.max_wasm_stack(1024 * 1024);

    // Enable optimizations for performance
    config.cranelift_opt_level(wasmtime::OptLevel::Speed);

    config
}

pub fn generate_linker(
    engine: &Engine,
) -> Result<Linker<MemoryManager>, Error> {
    let mut linker: Linker<MemoryManager> = Linker::new(engine);

    // functions are created for webasembly modules, the logic of which is programmed in Rust
    linker
        .func_wrap(
            "env",
            "pointer_len",
            |caller: Caller<'_, MemoryManager>, pointer: i32| {
                caller.data().get_pointer_len(pointer as usize)
                    as u32
            },
        )
        .map_err(|e| {
            Error::Compiler(format!("An error has occurred linking a function, module: env, name: pointer_len, {}", e))
        })?;

    linker
        .func_wrap(
            "env",
            "alloc",
            |mut caller: Caller<'_, MemoryManager>, len: u32| -> u32 {
                caller
                    .data_mut()
                    .alloc(len as usize)
                    .map(|ptr| ptr as u32)
                    .unwrap_or_else(|e| {
                        error!(TARGET_CONTRACT, "Allocation failed: {}", e);
                        0 // Return 0 to indicate allocation failure
                    })
            },
        )
        .map_err(|e| {
            Error::Compiler(format!("An error has occurred linking a function, module: env, name: alloc, {}", e))
        })?;

    linker
        .func_wrap(
            "env",
            "write_byte",
            |mut caller: Caller<'_, MemoryManager>, ptr: u32, offset: u32, data: u32| {
                caller
                    .data_mut()
                    .write_byte(ptr as usize, offset as usize, data as u8)
                    .unwrap_or_else(|e| {
                        error!(TARGET_CONTRACT, "Write failed: {}", e);
                    });
            },
        )
        .map_err(|e| {
            Error::Compiler(format!("An error has occurred linking a function, module: env, name: write_byte, {}", e))
        })?;

    linker
        .func_wrap(
            "env",
            "read_byte",
            |caller: Caller<'_, MemoryManager>, index: i32| {
                caller.data().read_byte(index as usize) as u32
            },
        )
        .map_err(|e| {
            Error::Compiler(format!("An error has occurred linking a function, module: env, name: read_byte, {}", e))
        })?;

    Ok(linker)
}

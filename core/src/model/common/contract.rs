use std::collections::HashMap;

use wasmtime::{
    Caller, Config, Engine, Error as WasmError, Linker, StoreLimits,
    StoreLimitsBuilder,
};

use thiserror::Error;

#[derive(Debug, Error, Clone)]
pub enum ContractError {
    #[error("memory allocation failed: {details}")]
    MemoryAllocationFailed { details: String },

    #[error("invalid pointer: {pointer}")]
    InvalidPointer { pointer: usize },

    #[error("write out of bounds: offset {offset} >= allocation size {size}")]
    WriteOutOfBounds { offset: usize, size: usize },

    #[error("allocation size {size} exceeds maximum of {max} bytes")]
    AllocationTooLarge { size: usize, max: usize },

    #[error("total memory {total} exceeds maximum of {max} bytes")]
    TotalMemoryExceeded { total: usize, max: usize },

    #[error("memory allocation would overflow")]
    AllocationOverflow,

    #[error("linker error [{function}]: {details}")]
    LinkerError {
        function: &'static str,
        details: String,
    },
}

#[derive(Debug)]
pub struct MemoryManager {
    memory: Vec<u8>,
    map: HashMap<usize, usize>,
    pub store_limits: StoreLimits,
}

impl Default for MemoryManager {
    fn default() -> Self {
        Self {
            memory: Vec::new(),
            map: HashMap::new(),
            // Limits applied to the WASM module's own linear memory and tables,
            // independent of the host-side MemoryManager buffer limits above.
            store_limits: StoreLimitsBuilder::new()
                .memory_size(8 * 1024 * 1024) // 8MB max WASM linear memory (2× estimated digital-twin peak of ~4MB)
                .table_elements(512)           // max function table entries (Rust contracts without dyn Trait use <50 real entries)
                .instances(1)
                .tables(1)
                .memories(1)
                .trap_on_grow_failure(true)
                .build(),
        }
    }
}

// Host-side MemoryManager limits (the buffer shared between host and WASM for I/O).
// These bound what can be passed in (state, event) and out (result) of a contract.
//
// Realistic sizes (e.g. digital-twin with many unit processes and sensor readings):
//   state_in   ~3-5 KB | event_in  ~10-100 KB
//   result_out ~100-500 KB | init_state ~1 KB
// 2MB per alloc and 6MB total gives >4x headroom over expected peaks.
const MAX_SINGLE_ALLOC: usize = 2 * 1024 * 1024; // 2MB per allocation
const MAX_TOTAL_MEMORY: usize = 6 * 1024 * 1024; // 6MB total I/O (state_in + event_in + init + result_out)

// Fuel limits for contract execution (~1 fuel unit per WASM instruction)
pub const MAX_FUEL: u64 = 10_000_000;
// Compilation/validation limit (one-time cost when new schemas are compiled)
pub const MAX_FUEL_COMPILATION: u64 = 50_000_000;

impl MemoryManager {
    pub fn alloc(&mut self, len: usize) -> Result<usize, ContractError> {
        // Security check: prevent excessive single allocations
        if len > MAX_SINGLE_ALLOC {
            return Err(ContractError::AllocationTooLarge {
                size: len,
                max: MAX_SINGLE_ALLOC,
            });
        }

        let current_len = self.memory.len();

        // Security check: prevent total memory exhaustion
        let new_len = current_len
            .checked_add(len)
            .ok_or(ContractError::AllocationOverflow)?;

        if new_len > MAX_TOTAL_MEMORY {
            return Err(ContractError::TotalMemoryExceeded {
                total: new_len,
                max: MAX_TOTAL_MEMORY,
            });
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
    ) -> Result<(), ContractError> {
        // Security check: validate pointer exists in allocation map
        let len = self
            .map
            .get(&start_ptr)
            .ok_or(ContractError::InvalidPointer { pointer: start_ptr })?;

        // Security check: validate write is within bounds
        if offset >= *len {
            return Err(ContractError::WriteOutOfBounds { offset, size: *len });
        }

        self.memory[start_ptr + offset] = data;
        Ok(())
    }

    pub fn read_byte(&self, ptr: usize) -> Result<u8, ContractError> {
        if ptr >= self.memory.len() {
            return Err(ContractError::InvalidPointer { pointer: ptr });
        }
        Ok(self.memory[ptr])
    }

    pub fn read_data(&self, ptr: usize) -> Result<&[u8], ContractError> {
        let len = self
            .map
            .get(&ptr)
            .ok_or(ContractError::InvalidPointer { pointer: ptr })?;
        Ok(&self.memory[ptr..ptr + len])
    }

    pub fn get_pointer_len(&self, ptr: usize) -> isize {
        let Some(result) = self.map.get(&ptr) else {
            return -1;
        };
        *result as isize
    }

    pub fn add_data_raw(
        &mut self,
        bytes: &[u8],
    ) -> Result<usize, ContractError> {
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
) -> Result<Linker<MemoryManager>, ContractError> {
    let mut linker: Linker<MemoryManager> = Linker::new(engine);

    // functions are created for webasembly modules, the logic of which is programmed in Rust
    linker
        .func_wrap(
            "env",
            "pointer_len",
            |caller: Caller<'_, MemoryManager>, pointer: i32| {
                caller.data().get_pointer_len(pointer as usize) as u32
            },
        )
        .map_err(|e| ContractError::LinkerError {
            function: "pointer_len",
            details: e.to_string(),
        })?;

    linker
        .func_wrap(
            "env",
            "alloc",
            |mut caller: Caller<'_, MemoryManager>,
             len: u32|
             -> Result<u32, WasmError> {
                caller
                    .data_mut()
                    .alloc(len as usize)
                    .map(|ptr| ptr as u32)
                    .map_err(WasmError::from)
            },
        )
        .map_err(|e| ContractError::LinkerError {
            function: "alloc",
            details: e.to_string(),
        })?;

    linker
        .func_wrap(
            "env",
            "write_byte",
            |mut caller: Caller<'_, MemoryManager>,
             ptr: u32,
             offset: u32,
             data: u32|
             -> Result<(), WasmError> {
                caller
                    .data_mut()
                    .write_byte(ptr as usize, offset as usize, data as u8)
                    .map_err(WasmError::from)
            },
        )
        .map_err(|e| ContractError::LinkerError {
            function: "write_byte",
            details: e.to_string(),
        })?;

    linker
        .func_wrap(
            "env",
            "read_byte",
            |caller: Caller<'_, MemoryManager>,
             index: i32|
             -> Result<u32, WasmError> {
                let ptr = usize::try_from(index)
                    .map_err(|_| ContractError::InvalidPointer { pointer: 0 })?;
                caller.data().read_byte(ptr).map(|b| b as u32).map_err(WasmError::from)
            },
        )
        .map_err(|e| ContractError::LinkerError {
            function: "read_byte",
            details: e.to_string(),
        })?;

    Ok(linker)
}
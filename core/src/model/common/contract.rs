use std::collections::HashMap;

use wasmtime::{
    Caller, Config, Engine, Error as WasmError, Linker, StoreLimits,
    StoreLimitsBuilder,
};

use thiserror::Error;

use crate::config::MachineSpec;

// ── WasmLimits ────────────────────────────────────────────────────────────────

/// Resolved wasmtime resource limits, ready to configure the engine and stores.
///
/// All limits are security upper-bounds. Typical digital-twin contracts use
/// kilobytes of state — these caps prevent runaway allocations by malicious or
/// buggy contracts.
#[derive(Debug, Clone)]
pub struct WasmLimits {
    /// Maximum WASM stack depth in bytes. Fixed for security regardless of RAM.
    pub max_wasm_stack: usize,
    /// Maximum WASM linear memory per contract instance (demand-paged virtual).
    pub memory_size: usize,
    /// Maximum single host-side I/O allocation (state_in, event_in, or result_out).
    pub max_single_alloc: usize,
    /// Maximum total host-side I/O buffer per contract call.
    pub max_total_memory: usize,
    /// WASM function-table cap. Scales with CPU: more cores → heavier contracts supported.
    pub max_table_elements: usize,
    /// Use Cranelift `SpeedAndSize` opt level (true when cpu_cores ≥ 4).
    /// Produces smaller, faster code at the cost of longer JIT compilation.
    pub aggressive_compilation: bool,
}

impl Default for WasmLimits {
    fn default() -> Self {
        Self::build(4_096, 2)
    }
}

impl WasmLimits {
    /// Derive resource limits from total machine RAM and CPU cores.
    ///
    /// ## Scaling rationale
    ///
    /// - **`memory_size`** (WASM linear memory): virtual and demand-paged, so the
    ///   cost is proportional to pages actually touched, not the cap. Scales from
    ///   4 MB (Nano) to 32 MB (Large+) to bound worst-case VM RSS per instance.
    ///
    /// - **`max_total_memory`** (host I/O): bounds the total byte-transfer between
    ///   host and WASM per call (state_in + event_in + result_out). Scales from
    ///   3 MB (Nano) to 24 MB (Medium+).
    ///
    /// - **`max_single_alloc`**: cap on a single buffer; ≈ ⅓ of total I/O budget.
    ///
    /// - **`max_wasm_stack`**: fixed at 1 MB — a security/correctness bound
    ///   independent of available RAM.
    ///
    /// - **`max_table_elements`** (WASM function table): scales with CPU cores.
    ///   Each Rust contract uses <50 real entries; this cap prevents runaway
    ///   tables in adversarial modules. 256 entries per core, floor 512, cap 2 048.
    ///
    /// - **`aggressive_compilation`**: enables Cranelift `SpeedAndSize` when
    ///   cpu_cores ≥ 4. Produces smaller, faster JIT code at the cost of longer
    ///   compilation time — only worthwhile when spare cores are available.
    ///
    /// - **Fuel limits** (`MAX_FUEL`, `MAX_FUEL_COMPILATION`): DOS-prevention
    ///   constants, machine-independent.
    pub fn build(ram_mb: u64, cpu_cores: usize) -> Self {
        // WASM linear memory per instance: floor 4 MB, cap 32 MB.
        let memory_size = ((ram_mb / 512) as usize)
            .saturating_mul(4 * 1024 * 1024)
            .clamp(4 * 1024 * 1024, 32 * 1024 * 1024);

        // Host I/O total per call: floor 3 MB, cap 24 MB.
        let max_total_memory = ((ram_mb / 512) as usize)
            .saturating_mul(3 * 1024 * 1024)
            .clamp(3 * 1024 * 1024, 24 * 1024 * 1024);

        // Single alloc cap ≈ ⅓ of I/O budget: floor 1 MB, cap 8 MB.
        let max_single_alloc =
            (max_total_memory / 3).clamp(1024 * 1024, 8 * 1024 * 1024);

        // Function table: 256 entries per core, floor 512, cap 2 048.
        let max_table_elements = (256 * cpu_cores.max(2)).min(2_048);

        Self {
            max_wasm_stack: 1024 * 1024, // 1 MB — security bound
            memory_size,
            max_single_alloc,
            max_total_memory,
            max_table_elements,
            // SpeedAndSize: slower to compile, faster/smaller output.
            // Only worthwhile when we have spare cores for the JIT.
            aggressive_compilation: cpu_cores >= 4,
        }
    }
}

/// Resolve wasmtime resource limits from a [`MachineSpec`]:
///
/// - `Profile(p)` → use the profile's canonical RAM and vCPU.
/// - `Custom { ram_mb, cpu_cores }` → use the supplied values directly.
/// - `None` → auto-detect total RAM and available CPU cores from the host.
pub fn resolve_wasm_limits(spec: Option<MachineSpec>) -> WasmLimits {
    let resolved = crate::config::resolve_spec(spec.as_ref());
    WasmLimits::build(resolved.ram_mb, resolved.cpu_cores)
}

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
    max_single_alloc: usize,
    max_total_memory: usize,
}

impl MemoryManager {
    /// Create a `MemoryManager` sized according to resolved [`WasmLimits`].
    pub fn from_limits(limits: &WasmLimits) -> Self {
        Self {
            memory: Vec::new(),
            map: HashMap::new(),
            // Limits applied to the WASM module's own linear memory and tables.
            store_limits: StoreLimitsBuilder::new()
                .memory_size(limits.memory_size)
                .table_elements(limits.max_table_elements) // scales with cpu_cores
                .instances(1)
                .tables(1)
                .memories(1)
                .trap_on_grow_failure(true)
                .build(),
            max_single_alloc: limits.max_single_alloc,
            max_total_memory: limits.max_total_memory,
        }
    }
}

impl Default for MemoryManager {
    fn default() -> Self {
        Self::from_limits(&WasmLimits::default())
    }
}

// Fuel limits for contract execution (~1 fuel unit per WASM instruction)
pub const MAX_FUEL: u64 = 10_000_000;
// Compilation/validation limit (one-time cost when new schemas are compiled)
pub const MAX_FUEL_COMPILATION: u64 = 50_000_000;

impl MemoryManager {
    pub fn alloc(&mut self, len: usize) -> Result<usize, ContractError> {
        // Security check: prevent excessive single allocations
        if len > self.max_single_alloc {
            return Err(ContractError::AllocationTooLarge {
                size: len,
                max: self.max_single_alloc,
            });
        }

        let current_len = self.memory.len();

        // Security check: prevent total memory exhaustion
        let new_len = current_len
            .checked_add(len)
            .ok_or(ContractError::AllocationOverflow)?;

        if new_len > self.max_total_memory {
            return Err(ContractError::TotalMemoryExceeded {
                total: new_len,
                max: self.max_total_memory,
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

/// Creates a secure Wasmtime engine configuration scaled to the given limits.
///
/// Shared between contract compilation and execution to ensure consistency.
/// The engine-level settings (fuel, stack, opt level) are performance/security
/// constants; only `max_wasm_stack` is taken from the resolved limits.
pub fn create_secure_wasmtime_config(limits: &WasmLimits) -> Config {
    let mut config = Config::default();

    // Enable fuel metering for gas-like execution limits.
    config.consume_fuel(true);

    // Stack depth cap: security bound, derived from resolved limits.
    config.max_wasm_stack(limits.max_wasm_stack);

    // SpeedAndSize on multi-core machines (≥4 cores): produces smaller, faster
    // JIT code. On low-core machines use Speed to keep compilation quick.
    let opt_level = if limits.aggressive_compilation {
        wasmtime::OptLevel::SpeedAndSize
    } else {
        wasmtime::OptLevel::Speed
    };
    config.cranelift_opt_level(opt_level);

    config
}

/// Wasmtime engine and resource limits bundled together.
///
/// Stored as a single system helper so actors only need one helper access
/// instead of two separate lookups for "engine" and "wasm_limits".
pub struct WasmRuntime {
    pub engine: Engine,
    pub limits: WasmLimits,
}

impl WasmRuntime {
    /// Build a `WasmRuntime` from an optional [`MachineSpec`].
    /// Returns an error if the Wasmtime engine cannot be created.
    pub fn new(spec: Option<MachineSpec>) -> Result<Self, wasmtime::Error> {
        let limits = resolve_wasm_limits(spec);
        let engine = Engine::new(&create_secure_wasmtime_config(&limits))?;
        Ok(Self { engine, limits })
    }
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
                let ptr = usize::try_from(index).map_err(|_| {
                    ContractError::InvalidPointer { pointer: 0 }
                })?;
                caller
                    .data()
                    .read_byte(ptr)
                    .map(|b| b as u32)
                    .map_err(WasmError::from)
            },
        )
        .map_err(|e| ContractError::LinkerError {
            function: "read_byte",
            details: e.to_string(),
        })?;

    Ok(linker)
}

# ave-types

TypeScript type definitions for the [Averiun Ledger](https://averiun.com) API.

Auto-generated from Rust source code using [ts-rs](https://github.com/Aleph-Alpha/ts-rs), ensuring perfect synchronization between backend types and frontend interfaces.

## Installation

```bash
npm install ave-types
```

## Usage

```typescript
import type {
  BridgeSignedEventRequest,
  BridgeEventRequest,
  BridgeCreateRequest,
  SubjectDB,
  RequestState,
  LedgerDB
} from "ave-types";

// Example: Create event request
const createRequest: BridgeEventRequest = {
  event: "create",
  data: {
    name: "My Subject",
    description: "Subject description",
    governance_id: "EqDbWS...",
    schema_id: "governance",
    namespace: ["example", "namespace"]
  }
};

// Example: Signed request
const signedRequest: BridgeSignedEventRequest = {
  request: createRequest,
  signature: {
    signer: "EqCxN...",
    timestamp: 1234567890,
    value: "EqD8z...",
    content_hash: "EqBqK..."
  }
};
```

## Available Types

### Request Types
- `BridgeSignedEventRequest` - Wrapper for signed event requests
- `BridgeEventRequest` - Event request (tagged union)
- `BridgeCreateRequest` - Create a new subject
- `BridgeFactRequest` - Add facts to a subject
- `BridgeTransferRequest` - Transfer subject ownership
- `BridgeConfirmRequest` - Confirm a transfer
- `BridgeRejectRequest` - Reject a transfer
- `BridgeEOLRequest` - Mark subject as end-of-life
- `EventRequestType` - Enum of event types: `"create" | "fact" | "transfer" | "confirm" | "reject" | "eol"`

### Response Types
- `SubjectDB` - Subject database record
- `LedgerDB` - Ledger event record with timestamps
- `RequestState` - Request processing state enum
- `RequestEventDB` - Database event representation (tagged union)
- `RequestInfo` - Request state and version
- `RequestInfoExtend` - Request state and version with request ID
- `RequestData` - Request ID and subject ID pair
- `SubjsData` - Subject metadata
- `GovsData` - Governance metadata
- `Paginator` - Pagination metadata
- `PaginatorEvents` - Paginated ledger events
- `PaginatorAborts` - Paginated abort events
- `AbortDB` - Abort event record
- `EvalResDB` - Evaluation result
- `RequestsInManager` - Request manager state
- `RequestsInManagerSubject` - Subject request queue state

### Query Types
- `SubjectQuery` - Filter subjects by `active` and/or `schema_id`
- `GovQuery` - Filter governances by `active`
- `EventsQuery` - Filter ledger events by time ranges, page, quantity, and event type
- `FirstEndEvents` - Query for first/last events by type and quantity
- `AbortsQuery` - Filter abort events by request ID, sn, page, and quantity
- `ApprovalQuery` - Filter approvals by state
- `TimeRange` - ISO 8601 time range filter

### Approval Types
- `ApprovalEntry` - Approval request combined with its current state
- `ApprovalReq` - Approval request data
- `ApprovalState` - Approval status: `"Pending" | "RespondedAccepted" | "RespondedRejected" | "Obsolete"`
- `ApprovalStateRes` - Approval response state (excludes `"Pending"`)

### Other Types
- `BridgeSignature` - Cryptographic signature with timestamp
- `TransferSubject` - Transfer subject data
- `MonitorNetworkState` - Network connectivity state
- `DataToSink` - Event sink data (tagged union)
- `DataToSinkEvent` - Sink event types (create, fact, transfer, etc.)
- `Namespace` - Subject namespace (`Array<string>`)
- `SchemaType` - Schema type: `"Governance" | { Type: string } | "TrackerSchemas"`
- `JsonValue` - Recursive JSON value type

## Type Notes

### Tagged Unions
Event types use TypeScript discriminated unions matching Rust's serde tag/content serialization:

```typescript
type BridgeEventRequest =
  | { event: "create"; data: BridgeCreateRequest }
  | { event: "fact"; data: BridgeFactRequest }
  | { event: "transfer"; data: BridgeTransferRequest }
  // ...
```

### Namespace
`Namespace` is an array of strings representing the hierarchical path of a subject:

```typescript
const ns: Namespace = ["example", "namespace"]; // Array<string>
```

### Number for u64/i64
Rust `u64` and `i64` fields (timestamps, sequence numbers) map to TypeScript `number` for JavaScript compatibility:

```typescript
const timestamp = 1234567890; // number
const sn = 42; // number
```

**Note:** The types are generated with `TS_RS_LARGE_INT=number` to ensure compatibility with JavaScript's number type instead of bigint.

### Optional Fields
Rust `Option<T>` becomes `T | null` in TypeScript:

```typescript
signature: BridgeSignature | null
```

## Development

### Generating Types

To regenerate the TypeScript bindings from Rust source:

```bash
# From common/ts directory
npm run generate

# Or directly
bash generate.sh
```

This will:
1. Run cargo tests with the `typescript` feature enabled
2. Export types to `src/` directory using ts-rs
3. Generate a barrel `index.ts` that re-exports all types
4. Use `TS_RS_LARGE_INT=number` to map Rust u64/i64 to TypeScript number

### Publishing Updates

When Rust types are modified:

```bash
# 1. Regenerate types
npm run generate

# 2. Bump version and publish
npm run release:patch   # 0.3.3 -> 0.3.4
npm run release:minor   # 0.3.3 -> 0.4.0
npm run release:major   # 0.3.3 -> 1.0.0
```

This will automatically:
- Regenerate the types
- Bump the package version
- Publish to npm with public access

## License

AGPL-3.0-only

## Links

- [Averiun Ledger](https://averiun.com)
- [GitHub Repository](https://github.com/Averiun-Ledger/ave)
- [API Documentation](https://docs.averiun.com) *(coming soon)*

---

**Generated from Rust** • Built with [ts-rs](https://github.com/Aleph-Alpha/ts-rs)

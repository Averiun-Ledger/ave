#!/usr/bin/env bash
# Generate TypeScript bindings from ave-common Rust types.
#
# Usage:
#   bash generate.sh            # regenerar tipos
#   npm run generate             # igual, desde common/ts/
#
# Publicar actualización a npm:
#   1. Modificar los tipos Rust en common/src/
#   2. bash generate.sh
#   3. npm version patch|minor|major
#   4. npm publish --access public
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
BINDINGS_DIR="$SCRIPT_DIR/src"

echo "Generating TypeScript bindings from Rust types..."

# Generate bindings via cargo test (ts-rs exports on test run)
# TS_RS_LARGE_INT=number ensures Rust u64/i64 types map to TypeScript number (not bigint)
TS_RS_EXPORT_DIR="$BINDINGS_DIR" \
  TS_RS_LARGE_INT=number \
  cargo test -p ave-common --features typescript \
  --manifest-path "$PROJECT_ROOT/Cargo.toml" 2>&1

# Generate barrel index.ts re-exporting all generated types
echo "Creating index.ts..."
INDEX_FILE="$BINDINGS_DIR/index.ts"
: > "$INDEX_FILE"

# Export top-level types
for ts_file in "$BINDINGS_DIR"/*.ts; do
  filename="$(basename "$ts_file")"
  [ "$filename" = "index.ts" ] && continue
  module="${filename%.ts}"
  echo "export type { ${module} } from \"./${module}\";" >> "$INDEX_FILE"
done

# Export types from subdirectories (e.g. serde_json/JsonValue)
find "$BINDINGS_DIR" -mindepth 2 -name '*.ts' | sort | while read -r ts_file; do
  rel="${ts_file#"$BINDINGS_DIR"/}"
  module="${rel%.ts}"
  type_name="$(basename "$module")"
  echo "export type { ${type_name} } from \"./${module}\";" >> "$INDEX_FILE"
done

echo "Done! TypeScript bindings generated in $BINDINGS_DIR"
// Package version holds the build identity of the fallow binary.
package version

// Version is the semantic version reported in every output document.
// It tracks the upstream fallow release whose CLI surface this port follows.
const Version = "3.42.0"

// SchemaVersion is the version of the JSON output envelope.
const SchemaVersion = 10

// HealthSchemaVersion is the version of the health JSON envelope.
const HealthSchemaVersion = 13

// ArchitectureSchemaVersion is the version of the architecture JSON envelope.
const ArchitectureSchemaVersion = 2

// SnapshotSchemaVersion is the version of a saved vital-signs snapshot.
const SnapshotSchemaVersion = 12

// ScoreFormulaVersion identifies the health score formula.
const ScoreFormulaVersion = 3

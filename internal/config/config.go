// Package config loads and resolves goose configuration files
// (.gooserc.json, goose.json, goose.toml) including
// extends chains, rule severities, and validation.
package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Severity is a rule severity.
type Severity string

const (
	Error Severity = "error"
	Warn  Severity = "warn"
	Off   Severity = "off"
)

// ParseSeverity accepts the three documented values.
func ParseSeverity(s string) (Severity, bool) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "error":
		return Error, true
	case "warn", "warning":
		return Warn, true
	case "off", "none":
		return Off, true
	}
	return "", false
}

// StringOrArray accepts a bare string or an array of strings.
type StringOrArray []string

func (s *StringOrArray) UnmarshalJSON(data []byte) error {
	var one string
	if err := json.Unmarshal(data, &one); err == nil {
		*s = []string{one}
		return nil
	}
	var many []string
	if err := json.Unmarshal(data, &many); err != nil {
		return fmt.Errorf("expected a string or an array of strings")
	}
	*s = many
	return nil
}

// ProductionMode accepts a boolean or a per-analysis object.
type ProductionMode struct {
	Enabled  bool
	DeadCode bool
	Health   bool
	Dupes    bool
	PerKey   bool
}

func (p *ProductionMode) UnmarshalJSON(data []byte) error {
	var b bool
	if err := json.Unmarshal(data, &b); err == nil {
		p.Enabled = b
		p.DeadCode = b
		p.Health = b
		p.Dupes = b
		return nil
	}
	var obj struct {
		DeadCode *bool `json:"deadCode"`
		Health   *bool `json:"health"`
		Dupes    *bool `json:"dupes"`
	}
	if err := json.Unmarshal(data, &obj); err != nil {
		return fmt.Errorf("production must be a boolean or an object with deadCode, health, and dupes")
	}
	p.PerKey = true
	p.DeadCode = obj.DeadCode != nil && *obj.DeadCode
	p.Health = obj.Health != nil && *obj.Health
	p.Dupes = obj.Dupes != nil && *obj.Dupes
	return nil
}

// IgnoreExportsUsedInFile accepts a boolean or the knip-compatible object.
type IgnoreExportsUsedInFile struct {
	Enabled bool
}

func (p *IgnoreExportsUsedInFile) UnmarshalJSON(data []byte) error {
	var b bool
	if err := json.Unmarshal(data, &b); err == nil {
		p.Enabled = b
		return nil
	}
	var obj map[string]bool
	if err := json.Unmarshal(data, &obj); err != nil {
		return fmt.Errorf("ignoreExportsUsedInFile must be a boolean or an object")
	}
	p.Enabled = obj["type"] || obj["interface"]
	return nil
}

// IgnoreExport names exports to suppress for a file glob.
type IgnoreExport struct {
	File    string   `json:"file"`
	Exports []string `json:"exports"`
}

// CatalogReference suppresses unresolved-catalog-reference findings.
type CatalogReference struct {
	Package  string `json:"package"`
	Catalog  string `json:"catalog"`
	Consumer string `json:"consumer"`
}

// DependencyOverride suppresses dependency-override findings.
type DependencyOverride struct {
	Package string `json:"package"`
	Source  string `json:"source"`
}

// TypeAware configures the optional TypeScript semantic pass.
type TypeAware struct {
	Enabled  bool     `json:"enabled"`
	Projects []string `json:"projects"`
	Require  string   `json:"require"` // best-effort | complete
}

// Security configures the security catalogue.
type Security struct {
	RequestReceivers []string `json:"requestReceivers"`
	Categories       struct {
		Include []string `json:"include"`
		Exclude []string `json:"exclude"`
	} `json:"categories"`
}

// Duplicates configures fallow dupes.
type Duplicates struct {
	Mode                     string          `json:"mode"`
	Near                     bool            `json:"near"`
	MinTokens                int             `json:"minTokens"`
	MinLines                 int             `json:"minLines"`
	MinOccurrences           int             `json:"minOccurrences"`
	Threshold                float64         `json:"threshold"`
	Enabled                  *bool           `json:"enabled"`
	Ignore                   []string        `json:"ignore"`
	IgnoredClones            []string        `json:"ignoredClones"`
	IgnoreDefaults           *bool           `json:"ignoreDefaults"`
	SkipLocal                bool            `json:"skipLocal"`
	CrossLanguage            bool            `json:"crossLanguage"`
	IgnoreImports            *bool           `json:"ignoreImports"`
	IgnoreSymlinks           bool            `json:"ignoreSymlinks"`
	Normalization            map[string]bool `json:"normalization"`
	MinCorpusSizeForShingle  int             `json:"minCorpusSizeForShingleFilter"`
	MinCorpusSizeForTokenCch int             `json:"minCorpusSizeForTokenCache"`
}

// SimilarCode configures the semantic similar-code workflow.
type SimilarCode struct {
	Threshold float64  `json:"threshold"`
	MinLines  int      `json:"minLines"`
	Ignore    []string `json:"ignore"`
}

// Mutation configures mutation testing.
type Mutation struct {
	Runner       string   `json:"runner"`
	Operators    []string `json:"operators"`
	MinScore     *float64 `json:"minScore"`
	Concurrency  int      `json:"concurrency"`
	Typecheck    bool     `json:"typecheck"`
	RunnerConfig string   `json:"runnerConfig"`
}

// ThresholdOverride raises complexity ceilings for matched code.
type ThresholdOverride struct {
	Files         []string `json:"files"`
	Functions     []string `json:"functions"`
	MaxCyclomatic *int     `json:"maxCyclomatic"`
	MaxCognitive  *int     `json:"maxCognitive"`
	MaxCrap       *float64 `json:"maxCrap"`
	MaxUnitSize   *int     `json:"maxUnitSize"`
	MaxFileLines  *int     `json:"maxFileLines"`
	Reason        string   `json:"reason"`
}

// Thresholds configures health metric ceilings.
type Thresholds struct {
	MaxCyclomatic int     `json:"maxCyclomatic"`
	MaxCognitive  int     `json:"maxCognitive"`
	MaxCrap       float64 `json:"maxCrap"`
	MaxUnitSize   int     `json:"maxUnitSize"`
	MaxFileLines  int     `json:"maxFileLines"`
}

// Ownership configures ownership analysis.
type Ownership struct {
	BotPatterns []string `json:"botPatterns"`
	EmailMode   string   `json:"emailMode"`
}

// ChangeCoupling configures change-coupling thresholds.
type ChangeCoupling struct {
	MinRevisions       int     `json:"minRevisions"`
	MinSharedRevisions int     `json:"minSharedRevisions"`
	MinDegree          float64 `json:"minDegree"`
	MaxFilesPerCommit  int     `json:"maxFilesPerCommit"`
}

// AnalysisTuning holds analysis-wide knobs, matching fallow's analysis
// section.
type AnalysisTuning struct {
	MaxFileSizeMb *float64 `json:"maxFileSizeMb"`
}

// MaxFileSize resolves the analysis size cap in MB: unset uses fallow's
// documented 256 MB default; an explicit 0 disables the guard.
func (c *Config) MaxFileSize() float64 {
	if c.Analysis.MaxFileSizeMb == nil {
		return 256
	}
	return *c.Analysis.MaxFileSizeMb
}

// Health configures fallow health.
type Health struct {
	MaxCyclomatic            *int                `json:"maxCyclomatic"`
	CyclomaticPolicy         string              `json:"cyclomaticPolicy"`
	MaxCognitive             *int                `json:"maxCognitive"`
	MaxCrap                  *float64            `json:"maxCrap"`
	MaxFileLines             *int                `json:"maxFileLines"`
	MaxUnitSize              *int                `json:"maxUnitSize"`
	CrapRefactorBand         *float64            `json:"crapRefactorBand"`
	Ignore                   []string            `json:"ignore"`
	Coverage                 string              `json:"coverage"`
	CoverageRoot             string              `json:"coverageRoot"`
	Ownership                Ownership           `json:"ownership"`
	ChangeCoupling           ChangeCoupling      `json:"changeCoupling"`
	ThresholdOverrides       []ThresholdOverride `json:"thresholdOverrides"`
	SuggestInlineSuppression *bool               `json:"suggestInlineSuppression"`
}

// Audit configures the pull-request gate.
type Audit struct {
	Gate             string `json:"gate"`
	Worsened         string `json:"worsened"`
	DeadCode         *bool  `json:"deadCode"`
	Health           *bool  `json:"health"`
	Dupes            *bool  `json:"dupes"`
	CSS              *bool  `json:"css"`
	CSSDeep          *bool  `json:"cssDeep"`
	CacheMaxAgeDays  *int   `json:"cacheMaxAgeDays"`
	DeadCodeBaseline string `json:"deadCodeBaseline"`
	HealthBaseline   string `json:"healthBaseline"`
	DupesBaseline    string `json:"dupesBaseline"`
	TypeAware        *bool  `json:"typeAware"`
}

// Fix configures fallow fix.
type Fix struct {
	Catalog struct {
		DeletePrecedingComments string `json:"deletePrecedingComments"`
	} `json:"catalog"`
}

// Workspaces adds workspace patterns.
type Workspaces struct {
	Patterns     []string                   `json:"patterns"`
	ChangedSince string                     `json:"changedSince"`
	Settings     map[string]json.RawMessage `json:"settings"`
}

// Override applies rule severities to file globs.
type Override struct {
	Files []string          `json:"files"`
	Rules map[string]string `json:"rules"`
}

// CircularDependencies configures cycle detection.
type CircularDependencies struct {
	IgnoreLazyImports bool `json:"ignoreLazyImports"`
}

// Effect configures Effect-specific rules.
type Effect struct {
	SchemaExportsAsTypes bool `json:"schemaExportsAsTypes"`
}

// Zone is an architecture boundary zone.
type Zone struct {
	Name         string   `json:"name"`
	Patterns     []string `json:"patterns"`
	Root         string   `json:"root"`
	AutoDiscover []string `json:"autoDiscover"`
}

// BoundaryRule allows a zone to import from listed zones.
type BoundaryRule struct {
	From  string   `json:"from"`
	Allow []string `json:"allow"`
	Deny  []string `json:"deny"`
}

// Coverage configures boundary coverage.
type BoundaryCoverage struct {
	RequireAllFiles bool     `json:"requireAllFiles"`
	AllowUnmatched  []string `json:"allowUnmatched"`
}

// Boundaries configures architecture zones.
type Boundaries struct {
	Preset   string           `json:"preset"`
	Zones    []Zone           `json:"zones"`
	Rules    []BoundaryRule   `json:"rules"`
	Coverage BoundaryCoverage `json:"coverage"`
}

// SDKPattern is a feature-flag SDK call pattern.
type SDKPattern struct {
	Function string `json:"function"`
	NameArg  int    `json:"nameArg"`
	Provider string `json:"provider"`
}

// Flags configures feature-flag detection.
type Flags struct {
	SDKPatterns            []SDKPattern `json:"sdkPatterns"`
	EnvPrefixes            []string     `json:"envPrefixes"`
	ConfigObjectHeuristics bool         `json:"configObjectHeuristics"`
	VendorKeyPrefix        string       `json:"vendorKeyPrefix"`
}

// Resolve configures module resolution conditions.
type Resolve struct {
	Conditions []string `json:"conditions"`
}

// Framework is an inline framework plugin.
type Framework struct {
	Name        string   `json:"name"`
	Entry       []string `json:"entry"`
	Ignore      []string `json:"ignore"`
	Test        []string `json:"test"`
	UsedExports []struct {
		Pattern string `json:"pattern"`
	} `json:"usedExports"`
	ManifestEntries []struct {
		Manifests []string `json:"manifests"`
	} `json:"manifestEntries"`
}

// Cache configures the incremental cache.
type Cache struct {
	Dir       string `json:"dir"`
	MaxSizeMB int    `json:"maxSizeMb"`
}

// Regression holds the regression baseline.
type Regression struct {
	Baseline map[string]float64 `json:"baseline"`
}

// Config is a fully resolved project configuration.
type Config struct {
	Schema                    string                  `json:"$schema"`
	MinimumVersion            string                  `json:"minimumVersion"`
	Sealed                    bool                    `json:"sealed"`
	Extends                   StringOrArray           `json:"extends"`
	Entry                     []string                `json:"entry"`
	SupportEntry              []string                `json:"supportEntry"`
	IgnorePatterns            []string                `json:"ignorePatterns"`
	IgnoreFindings            []string                `json:"ignoreFindings"`
	IgnoreDependencies        []string                `json:"ignoreDependencies"`
	IgnoreBinaries            []string                `json:"ignoreBinaries"`
	IgnoreCommandEntries      []string                `json:"ignoreCommandEntries"`
	IgnoreCatalogReferences   []CatalogReference      `json:"ignoreCatalogReferences"`
	IgnoreDependencyOverrides []DependencyOverride    `json:"ignoreDependencyOverrides"`
	IgnoreUnresolvedImports   []string                `json:"ignoreUnresolvedImports"`
	IgnoreExports             []IgnoreExport          `json:"ignoreExports"`
	IgnoreExportsUsedInFile   IgnoreExportsUsedInFile `json:"ignoreExportsUsedInFile"`
	IncludeEntryExports       bool                    `json:"includeEntryExports"`
	ShowCascade               bool                    `json:"showCascade"`
	TypeAware                 TypeAware               `json:"typeAware"`
	Security                  Security                `json:"security"`
	AutoImports               bool                    `json:"autoImports"`
	IgnoreDecorators          []string                `json:"ignoreDecorators"`
	UnusedComponentProps      struct {
		IgnorePattern string `json:"ignorePattern"`
	} `json:"unusedComponentProps"`
	UsedClassMembers     []json.RawMessage    `json:"usedClassMembers"`
	PublicPackages       []string             `json:"publicPackages"`
	DynamicallyLoaded    []string             `json:"dynamicallyLoaded"`
	MarkupExtensions     []string             `json:"markupExtensions"`
	Duplicates           Duplicates           `json:"duplicates"`
	SimilarCode          SimilarCode          `json:"similarCode"`
	Mutation             Mutation             `json:"mutation"`
	Health               Health               `json:"health"`
	Thresholds           Thresholds           `json:"thresholds"`
	Audit                Audit                `json:"audit"`
	Fix                  Fix                  `json:"fix"`
	Production           ProductionMode       `json:"production"`
	Workspaces           Workspaces           `json:"workspaces"`
	Overrides            []Override           `json:"overrides"`
	CircularDependencies CircularDependencies `json:"circularDependencies"`
	Effect               Effect               `json:"effect"`
	Boundaries           Boundaries           `json:"boundaries"`
	RulePacks            []string             `json:"rulePacks"`
	Rules                map[string]string    `json:"rules"`
	Flags                Flags                `json:"flags"`
	Resolve              Resolve              `json:"resolve"`
	Codeowners           string               `json:"codeowners"`
	Framework            []Framework          `json:"framework"`
	Plugins              []string             `json:"plugins"`
	Cache                Cache                `json:"cache"`
	Regression           Regression           `json:"regression"`
	Analysis             AnalysisTuning       `json:"analysis"`
	FailOnParseError     bool                 `json:"failOnParseError"`

	// Resolved at load time, not part of the document.
	Root       string `json:"-"`
	LoadedFrom string `json:"-"`
	NoCache    bool   `json:"-"`
}

// Defaults returns the documented default configuration.
func Defaults() *Config {
	enabled := true
	ignoreDefaults := true
	ignoreImports := true
	suggest := true
	maxCyc, maxCog, maxUnit := 20, 15, 60
	maxCrap := 30.0
	band := 5.0
	return &Config{
		Duplicates: Duplicates{
			Mode:                     "mild",
			MinTokens:                50,
			MinLines:                 5,
			MinOccurrences:           2,
			Enabled:                  &enabled,
			IgnoreDefaults:           &ignoreDefaults,
			IgnoreImports:            &ignoreImports,
			MinCorpusSizeForShingle:  1024,
			MinCorpusSizeForTokenCch: 5000,
		},
		SimilarCode: SimilarCode{Threshold: 0.8, MinLines: 3},
		Mutation:    Mutation{Runner: "auto", Concurrency: 0},
		Health: Health{
			MaxCyclomatic:            &maxCyc,
			MaxCognitive:             &maxCog,
			MaxUnitSize:              &maxUnit,
			MaxCrap:                  &maxCrap,
			CrapRefactorBand:         &band,
			CyclomaticPolicy:         "standard",
			SuggestInlineSuppression: &suggest,
			ChangeCoupling: ChangeCoupling{
				MinRevisions:       5,
				MinSharedRevisions: 5,
				MinDegree:          0.3,
				MaxFilesPerCommit:  30,
			},
			Ownership: Ownership{EmailMode: "handle"},
		},
		Thresholds: Thresholds{
			MaxCyclomatic: 20,
			MaxCognitive:  15,
			MaxUnitSize:   60,
			MaxCrap:       30.0,
		},
		Audit:                Audit{Gate: "new-only", Worsened: "warn"},
		CircularDependencies: CircularDependencies{},
		Rules:                map[string]string{},
	}
}

// fileNames lists config file names in discovery precedence. Goose names
// first; the fallow spellings stay accepted for ports of existing configs.
var fileNames = []string{
	".gooserc.json", ".gooserc.jsonc", "goose.json", "goose.toml", ".goose.toml",
	".fallowrc.json", ".fallowrc.jsonc", "fallow.toml", ".fallow.toml",
}

// LoadOptions controls Discover.
type LoadOptions struct {
	Root               string
	Config             string // explicit --config path
	AllowRemoteExtends bool
}

// Discover finds and loads the nearest config.
func Discover(opts LoadOptions) (*Config, []string, error) {
	if opts.Root == "" {
		opts.Root = "."
	}
	root, err := filepath.Abs(opts.Root)
	if err != nil {
		return nil, nil, err
	}
	cfg := Defaults()
	cfg.Root = root
	var warnings []string
	if opts.Config != "" {
		path := opts.Config
		if !filepath.IsAbs(path) {
			path = filepath.Join(root, path)
		}
		loaded, w, err := loadFile(path, opts, nil, 0)
		if err != nil {
			return nil, nil, err
		}
		warnings = append(warnings, w...)
		cfg = loaded
		cfg.Root = root
		cfg.LoadedFrom = path
	} else {
		dir := root
		for {
			var best string
			for _, name := range fileNames {
				candidate := filepath.Join(dir, name)
				if _, statErr := os.Stat(candidate); statErr == nil {
					if best != "" {
						warnings = append(warnings, fmt.Sprintf("goose: ignoring config %q because %q takes precedence", candidate, best))
					}
					if best == "" {
						best = candidate
					}
				}
			}
			if best != "" {
				loaded, w, err := loadFile(best, opts, nil, 0)
				if err != nil {
					return nil, nil, err
				}
				warnings = append(warnings, w...)
				loaded.Root = root
				loaded.LoadedFrom = best
				cfg = loaded
				break
			}
			parent := filepath.Dir(dir)
			if parent == dir {
				break
			}
			dir = parent
		}
	}
	cfg.applyDefaults()
	return cfg, warnings, nil
}

func loadFile(path string, opts LoadOptions, seen []string, depth int) (*Config, []string, error) {
	raw, warnings, err := loadRawFile(path, opts, seen, depth)
	if err != nil {
		return nil, nil, err
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, nil, err
	}
	var sources []string
	if ext, ok := raw["extends"]; ok {
		switch v := ext.(type) {
		case string:
			sources = []string{v}
		case []string:
			sources = v
		case []any:
			for _, item := range v {
				if s, ok := item.(string); ok {
					sources = append(sources, s)
				}
			}
		}
		delete(raw, "extends")
	}

	mergedBytes, err := json.Marshal(raw)
	if err != nil {
		return nil, nil, err
	}
	base := Defaults()
	base.Extends = sources
	base.Rules = map[string]string{}
	if err := json.Unmarshal(mergedBytes, base); err != nil {
		return nil, nil, fmt.Errorf("invalid config %s: %w", abs, err)
	}
	base.applyDefaults()
	if base.MinimumVersion != "" {
		cmp, ok := compareVersion(Version(), base.MinimumVersion)
		if ok && cmp < 0 {
			return nil, nil, fmt.Errorf("%s requires goose %s or newer, running %s.\nUpgrade goose, or remove minimumVersion and the fields that need it.", filepath.Base(abs), base.MinimumVersion, Version())
		}
	}
	if base.Sealed {
		for _, src := range base.Extends {
			if strings.HasPrefix(src, "npm:") || strings.HasPrefix(src, "https:") || strings.HasPrefix(src, "http:") {
				return nil, nil, fmt.Errorf("sealed config %s cannot extend %q", abs, src)
			}
		}
	}
	return base, warnings, nil
}

func loadRawFile(path string, opts LoadOptions, seen []string, depth int) (map[string]any, []string, error) {
	if depth > 10 {
		return nil, nil, fmt.Errorf("config extends chain is deeper than 10 levels at %s", path)
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, nil, err
	}
	for _, s := range seen {
		if s == abs {
			return nil, nil, fmt.Errorf("circular extends: %s", abs)
		}
	}
	data, err := os.ReadFile(abs)
	if err != nil {
		return nil, nil, fmt.Errorf("cannot read config %s: %w", abs, err)
	}
	var raw map[string]any
	switch strings.ToLower(filepath.Ext(abs)) {
	case ".toml":
		raw, err = ParseTOML(string(data))
	default:
		raw, err = ParseJSONC(string(data))
	}
	if err != nil {
		return nil, nil, fmt.Errorf("invalid config %s: %w", abs, err)
	}
	return resolveRawExtends(abs, raw, opts, append(seen, abs), depth)
}

func resolveRawExtends(abs string, raw map[string]any, opts LoadOptions, seen []string, depth int) (map[string]any, []string, error) {
	var warnings []string
	ext, hasExtends := raw["extends"]
	if hasExtends {
		var sources []string
		switch v := ext.(type) {
		case string:
			sources = []string{v}
		case []string:
			sources = v
		case []any:
			for _, item := range v {
				if s, ok := item.(string); ok {
					sources = append(sources, s)
				}
			}
		}
		delete(raw, "extends")

		cleanBytes, err := json.Marshal(raw)
		if err != nil {
			return nil, nil, err
		}
		var dummy Config
		if err := decodeStrict(cleanBytes, &dummy); err != nil {
			return nil, nil, fmt.Errorf("invalid config %s: %w", abs, err)
		}

		acc := map[string]any{}
		for _, src := range sources {
			parentRaw, w, err := resolveExtendRaw(src, abs, opts, seen, depth+1)
			if err != nil {
				return nil, nil, err
			}
			warnings = append(warnings, w...)
			acc = deepMerge(acc, parentRaw)
		}
		merged := deepMerge(acc, raw)
		merged["extends"] = sources
		return merged, warnings, nil
	}

	cleanBytes, err := json.Marshal(raw)
	if err != nil {
		return nil, nil, err
	}
	var dummy Config
	if err := decodeStrict(cleanBytes, &dummy); err != nil {
		return nil, nil, fmt.Errorf("invalid config %s: %w", abs, err)
	}
	return raw, warnings, nil
}

func resolveExtendRaw(src, from string, opts LoadOptions, seen []string, depth int) (map[string]any, []string, error) {
	switch {
	case strings.HasPrefix(src, "https://"):
		if !opts.AllowRemoteExtends {
			return nil, nil, fmt.Errorf("config extends %q is an HTTPS URL; pass --allow-remote-extends to allow it", src)
		}
		data, err := fetchURL(src)
		if err != nil {
			return nil, nil, err
		}
		var raw map[string]any
		if strings.HasSuffix(src, ".toml") {
			raw, err = ParseTOML(string(data))
		} else {
			raw, err = ParseJSONC(string(data))
		}
		if err != nil {
			return nil, nil, fmt.Errorf("invalid config %s: %w", src, err)
		}
		return resolveRawExtends(src, raw, opts, seen, depth)
	case strings.HasPrefix(src, "http://"):
		return nil, nil, fmt.Errorf("config extends %q must use https://", src)
	case strings.HasPrefix(src, "npm:"):
		return loadNpmExtendRaw(strings.TrimPrefix(src, "npm:"), from, opts, seen, depth)
	default:
		path := src
		if !filepath.IsAbs(path) {
			path = filepath.Join(filepath.Dir(from), path)
		}
		return loadRawFile(path, opts, seen, depth)
	}
}

func loadNpmExtendRaw(pkg, from string, opts LoadOptions, seen []string, depth int) (map[string]any, []string, error) {
	dir := filepath.Dir(from)
	for {
		candidate := filepath.Join(dir, "node_modules", pkg)
		if info, err := os.Stat(candidate); err == nil && info.IsDir() {
			manifest := filepath.Join(candidate, "package.json")
			var pkgJSON struct {
				Main   string `json:"main"`
				Fallow string `json:"fallow"`
			}
			if data, err := os.ReadFile(manifest); err == nil {
				_ = json.Unmarshal(data, &pkgJSON)
			}
			entry := pkgJSON.Fallow
			if entry == "" {
				entry = pkgJSON.Main
			}
			if entry == "" {
				entry = "index.json"
			}
			return loadRawFile(filepath.Join(candidate, entry), opts, seen, depth)
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	return nil, nil, fmt.Errorf("cannot resolve npm extends %q from %s", pkg, from)
}


func decodeStrict(data []byte, target *Config) error {
	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(target); err != nil {
		return friendlyDecodeError(err)
	}
	return nil
}

func friendlyDecodeError(err error) error {
	msg := err.Error()
	if strings.Contains(msg, "unknown field") {
		return fmt.Errorf("%s. Check the field name; unknown keys fail the run with exit code 2", msg)
	}
	return err
}

func (c *Config) applyDefaults() {
	d := Defaults()
	if c.Duplicates.Mode == "" {
		c.Duplicates.Mode = d.Duplicates.Mode
	}
	if c.Duplicates.MinTokens == 0 {
		c.Duplicates.MinTokens = d.Duplicates.MinTokens
	}
	if c.Duplicates.MinLines == 0 {
		c.Duplicates.MinLines = d.Duplicates.MinLines
	}
	if c.Duplicates.MinOccurrences == 0 {
		c.Duplicates.MinOccurrences = d.Duplicates.MinOccurrences
	}
	if c.Duplicates.Enabled == nil {
		c.Duplicates.Enabled = d.Duplicates.Enabled
	}
	if c.Duplicates.IgnoreDefaults == nil {
		c.Duplicates.IgnoreDefaults = d.Duplicates.IgnoreDefaults
	}
	if c.Duplicates.IgnoreImports == nil {
		c.Duplicates.IgnoreImports = d.Duplicates.IgnoreImports
	}
	if c.Duplicates.MinCorpusSizeForShingle == 0 {
		c.Duplicates.MinCorpusSizeForShingle = d.Duplicates.MinCorpusSizeForShingle
	}
	if c.Duplicates.MinCorpusSizeForTokenCch == 0 {
		c.Duplicates.MinCorpusSizeForTokenCch = d.Duplicates.MinCorpusSizeForTokenCch
	}
	if c.SimilarCode.Threshold == 0 {
		c.SimilarCode.Threshold = d.SimilarCode.Threshold
	}
	if c.SimilarCode.MinLines == 0 {
		c.SimilarCode.MinLines = d.SimilarCode.MinLines
	}
	if c.Mutation.Runner == "" {
		c.Mutation.Runner = d.Mutation.Runner
	}
	h := &c.Health
	if c.Thresholds.MaxCyclomatic != 0 {
		h.MaxCyclomatic = &c.Thresholds.MaxCyclomatic
	} else if h.MaxCyclomatic != nil {
		c.Thresholds.MaxCyclomatic = *h.MaxCyclomatic
	} else {
		c.Thresholds.MaxCyclomatic = *d.Health.MaxCyclomatic
		h.MaxCyclomatic = &c.Thresholds.MaxCyclomatic
	}
	if c.Thresholds.MaxCognitive != 0 {
		h.MaxCognitive = &c.Thresholds.MaxCognitive
	} else if h.MaxCognitive != nil {
		c.Thresholds.MaxCognitive = *h.MaxCognitive
	} else {
		c.Thresholds.MaxCognitive = *d.Health.MaxCognitive
		h.MaxCognitive = &c.Thresholds.MaxCognitive
	}
	if c.Thresholds.MaxUnitSize != 0 {
		h.MaxUnitSize = &c.Thresholds.MaxUnitSize
	} else if h.MaxUnitSize != nil {
		c.Thresholds.MaxUnitSize = *h.MaxUnitSize
	} else {
		c.Thresholds.MaxUnitSize = *d.Health.MaxUnitSize
		h.MaxUnitSize = &c.Thresholds.MaxUnitSize
	}
	if c.Thresholds.MaxCrap != 0 {
		h.MaxCrap = &c.Thresholds.MaxCrap
	} else if h.MaxCrap != nil {
		c.Thresholds.MaxCrap = *h.MaxCrap
	} else {
		c.Thresholds.MaxCrap = *d.Health.MaxCrap
		h.MaxCrap = &c.Thresholds.MaxCrap
	}
	if c.Thresholds.MaxFileLines != 0 {
		h.MaxFileLines = &c.Thresholds.MaxFileLines
	} else if h.MaxFileLines != nil {
		c.Thresholds.MaxFileLines = *h.MaxFileLines
	}
	if h.CrapRefactorBand == nil {
		h.CrapRefactorBand = d.Health.CrapRefactorBand
	}
	if h.SuggestInlineSuppression == nil {
		h.SuggestInlineSuppression = d.Health.SuggestInlineSuppression
	}
	if h.CyclomaticPolicy == "" {
		h.CyclomaticPolicy = d.Health.CyclomaticPolicy
	}
	if h.ChangeCoupling.MinRevisions == 0 {
		h.ChangeCoupling.MinRevisions = d.Health.ChangeCoupling.MinRevisions
	}
	if h.ChangeCoupling.MinSharedRevisions == 0 {
		h.ChangeCoupling.MinSharedRevisions = d.Health.ChangeCoupling.MinSharedRevisions
	}
	if h.ChangeCoupling.MinDegree == 0 {
		h.ChangeCoupling.MinDegree = d.Health.ChangeCoupling.MinDegree
	}
	if h.ChangeCoupling.MaxFilesPerCommit == 0 {
		h.ChangeCoupling.MaxFilesPerCommit = d.Health.ChangeCoupling.MaxFilesPerCommit
	}
	if h.Ownership.EmailMode == "" {
		h.Ownership.EmailMode = d.Health.Ownership.EmailMode
	}
	if c.Audit.Gate == "" {
		c.Audit.Gate = d.Audit.Gate
	}
	if c.Audit.Worsened == "" {
		c.Audit.Worsened = d.Audit.Worsened
	}
	if c.Rules == nil {
		c.Rules = map[string]string{}
	}
}

// Merge returns child on top of parent: objects deep-merge, arrays replace.
func Merge(parent, child *Config) *Config {
	if parent == nil {
		return child
	}
	if child == nil {
		return parent
	}
	pj, _ := json.Marshal(parent)
	cj, _ := json.Marshal(child)
	var pm, cm map[string]any
	_ = json.Unmarshal(pj, &pm)
	_ = json.Unmarshal(cj, &cm)
	merged := deepMerge(pm, cm)
	data, _ := json.Marshal(merged)
	res := Defaults()
	res.Rules = map[string]string{}
	if err := json.Unmarshal(data, res); err != nil {
		return child
	}
	res.Root = child.Root
	res.LoadedFrom = child.LoadedFrom
	return res
}

func deepMerge(a, b map[string]any) map[string]any {
	out := map[string]any{}
	for k, v := range a {
		out[k] = v
	}
	for k, v := range b {
		av, aok := out[k]
		if bm, ok := v.(map[string]any); ok {
			if am, ok2 := av.(map[string]any); ok2 && aok {
				out[k] = deepMerge(am, bm)
				continue
			}
		}
		out[k] = v
	}
	return out
}

// RuleSeverity returns the resolved severity for a finding kind, applying
// top-level rules, file overrides, and the documented default.
func (c *Config) RuleSeverity(rule, path string) Severity {
	canonical := CanonicalRule(rule)
	sev := DefaultSeverity(canonical)
	if raw, ok := c.Rules[canonical]; ok {
		if s, ok := ParseSeverity(raw); ok {
			sev = s
		}
	}
	// Aliases can also be configured.
	for alias, canon := range ruleAliases {
		if canon != canonical {
			continue
		}
		if raw, ok := c.Rules[alias]; ok {
			if s, ok := ParseSeverity(raw); ok {
				sev = s
			}
		}
	}
	if path != "" {
		for _, ov := range c.Overrides {
			matched := false
			for _, g := range ov.Files {
				if MatchPath(g, path) {
					matched = true
					break
				}
			}
			if !matched {
				continue
			}
			matchedRule := false
			for name, raw := range ov.Rules {
				if CanonicalRule(name) == canonical {
					if s, ok := ParseSeverity(raw); ok {
						sev = s
						matchedRule = true
					}
				}
			}
			if !matchedRule {
				if raw, ok := ov.Rules["*"]; ok {
					if s, ok := ParseSeverity(raw); ok {
						sev = s
					}
				}
			}
		}
	}
	return sev
}

// RuleEnabled reports whether a rule runs at all.
func (c *Config) RuleEnabled(rule string) bool {
	return c.RuleSeverity(rule, "") != Off
}

// ProdFor reports whether production mode is on for an analysis.
func (c *Config) ProdFor(analysis string) bool {
	if !c.Production.PerKey && !c.Production.Enabled {
		return false
	}
	if !c.Production.PerKey {
		return c.Production.Enabled
	}
	switch analysis {
	case "dead-code":
		return c.Production.DeadCode
	case "health":
		return c.Production.Health
	case "dupes":
		return c.Production.Dupes
	}
	return false
}

// MatchPath compiles a glob with path semantics.
func MatchPath(pattern, path string) bool {
	p, err := compilePath(pattern)
	if err != nil {
		return false
	}
	return p.Match(path)
}

// SortedRules returns rule names in stable order, for config output.
func SortedRules() []string {
	names := make([]string, 0, len(ruleDefaults))
	for name := range ruleDefaults {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

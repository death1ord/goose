package config

// Threshold accessors resolve the pointer fields on Health so analyses never
// dereference nil. Defaults come from Defaults().

// MaxCyclomatic returns the cyclomatic ceiling, default 20.
func (c *Config) MaxCyclomatic() int {
	if c.Thresholds.MaxCyclomatic != 0 {
		return c.Thresholds.MaxCyclomatic
	}
	return intVal(c.Health.MaxCyclomatic, 20)
}

// MaxCognitive returns the cognitive ceiling, default 15.
func (c *Config) MaxCognitive() int {
	if c.Thresholds.MaxCognitive != 0 {
		return c.Thresholds.MaxCognitive
	}
	return intVal(c.Health.MaxCognitive, 15)
}

// MaxCrapF returns the CRAP ceiling, default 30.
func (c *Config) MaxCrapF() float64 {
	if c.Thresholds.MaxCrap != 0 {
		return c.Thresholds.MaxCrap
	}
	return floatVal(c.Health.MaxCrap, 30)
}

// MaxUnitSize returns the large-function line ceiling, default 60.
func (c *Config) MaxUnitSize() int {
	if c.Thresholds.MaxUnitSize != 0 {
		return c.Thresholds.MaxUnitSize
	}
	return intVal(c.Health.MaxUnitSize, 60)
}

// MaxFileLines returns the file-length ceiling, default 0 (off).
func (c *Config) MaxFileLines() int {
	if c.Thresholds.MaxFileLines != 0 {
		return c.Thresholds.MaxFileLines
	}
	return intVal(c.Health.MaxFileLines, 0)
}

// SuggestInlineSuppression reports whether health emits suppress-line hints.
func (c *Config) SuggestInline() bool {
	if c.Health.SuggestInlineSuppression == nil {
		return true
	}
	return *c.Health.SuggestInlineSuppression
}

// CyclomaticPolicy is "standard" or "literal-membership".
func (c *Config) CyclomaticPolicy() string {
	if c.Health.CyclomaticPolicy == "" {
		return "standard"
	}
	return c.Health.CyclomaticPolicy
}

func intVal(p *int, def int) int {
	if p == nil {
		return def
	}
	return *p
}

func floatVal(p *float64, def float64) float64 {
	if p == nil {
		return def
	}
	return *p
}

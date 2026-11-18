package report

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

// Review envelopes: the provider-ready comment sets rendered by
// --format review-github / review-gitlab, mirroring fallow's contract. A
// consumer posts `comments[]` as inline review threads and `body` as the
// sticky summary; the `<!-- goose-fingerprint:v1: ... -->` markers in every
// body carry the stable finding id so a later run reconciles threads (post
// new, update existing, resolve stale) without double-posting.

// markerPrefixV1 opens the fingerprint marker in every review body.
const markerPrefixV1 = "<!-- goose-fingerprint:v1: "

// markerSuffixV1 closes the fingerprint marker.
const markerSuffixV1 = " -->"

// reviewIDMarker is the sticky summary marker of the whole run.
const reviewIDMarker = "<!-- goose-review -->"

// markerRegexV1 finds goose markers in existing PR/MR comments.
const markerRegexV1 = `^<!-- goose-fingerprint:v1: ((?:[a-z]+:)?[0-9a-f]{16}) -->\s*$`

// ReviewEnvelope is the review-github / review-gitlab JSON document.
type ReviewEnvelope struct {
	Event       string          `json:"event,omitempty"` // COMMENT (GitHub only)
	Body        string          `json:"body"`
	Summary     ReviewSummary   `json:"summary"`
	Comments    []ReviewComment `json:"comments"`
	MarkerRegex string          `json:"marker_regex"`
	MarkerFlags string          `json:"marker_regex_flags"`
	Meta        ReviewMeta      `json:"meta"`
}

// ReviewSummary is the sticky summary comment with its own fingerprint.
type ReviewSummary struct {
	Body        string `json:"body"`
	Fingerprint string `json:"fingerprint"`
}

// ReviewMeta identifies the envelope producer.
type ReviewMeta struct {
	Schema          string  `json:"schema"`
	Provider        string  `json:"provider"`
	CheckConclusion *string `json:"check_conclusion,omitempty"` // GitHub only
}

// ReviewComment is one inline comment; GitHub and GitLab shapes differ and
// each entry carries only its provider's fields.
type ReviewComment struct {
	// GitHub fields.
	Path string `json:"path,omitempty"`
	Line int    `json:"line,omitempty"`
	Side string `json:"side,omitempty"`
	// GitLab field: the diff position object.
	Position map[string]any `json:"position,omitempty"`
	// Shared.
	Body        string `json:"body"`
	Fingerprint string `json:"fingerprint"`
}

// fingerprintHash renders the stable lowercase 16-hex marker value used in
// review-comment bodies. Input-independent length keeps every marker the same
// shape whether it comes from a finding id or a summary body.
func fingerprintHash(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:8])
}

// ReviewGithub renders the GitHub review envelope.
func (d *Doc) ReviewGithub(o Options) string {
	return d.reviewEnvelope("github", o)
}

// ReviewGitlab renders the GitLab merge-request review envelope.
func (d *Doc) ReviewGitlab(o Options) string {
	return d.reviewEnvelope("gitlab", o)
}

func (d *Doc) reviewEnvelope(provider string, o Options) string {
	visible := d.Visible()
	var comments []ReviewComment
	limit := 50
	for _, f := range visible {
		if len(comments) >= limit {
			break
		}
		if f.Line == 0 || f.Path == "" || f.Path == "go.mod" || f.Path == "go.work" {
			continue // no position to anchor
		}
		fp := f.ID
		if fp == "" {
			fp = Fingerprint(f.Kind, f.Path, f.Message)
		}
		markerFP := fingerprintHash(fp)
		body := fmt.Sprintf("**goose: %s**\n\n%s", f.Kind, f.Message)
		if len(f.Actions) > 0 && f.Actions[0].Description != "" {
			body += "\n\n" + f.Actions[0].Description
		}
		body += "\n\n" + markerPrefixV1 + markerFP + markerSuffixV1
		c := ReviewComment{Body: body, Fingerprint: markerFP}
		p := withPrefix(f.Path, o.Prefix)
		if provider == "github" {
			c.Path, c.Line, c.Side = p, f.Line, "RIGHT"
		} else {
			c.Position = map[string]any{
				"position_type": "text",
				"new_path":      p,
				"new_line":      f.Line,
				"old_path":      p,
			}
		}
		comments = append(comments, c)
	}

	truncation := ""
	if len(visible) > len(comments) {
		truncation = fmt.Sprintf("\n\n_%d more findings not shown inline._", len(visible)-len(comments))
	}
	mark := "✅"
	if d.HasErrorSeverity() || d.gateFailedLocked() {
		mark = "❌"
	} else if d.WarnCount() > 0 {
		mark = "⚠️"
	}
	summaryText := fmt.Sprintf("%s **goose**: %d finding(s) · %s %s\n%s",
		mark, len(visible), d.Mark(), d.tailCounts(), reviewIDMarker)
	summaryBody := summaryText + truncation + "\n\n" +
		markerPrefixV1 + fingerprintHash(summaryText) + markerSuffixV1

	env := ReviewEnvelope{
		Body:        summaryBody,
		Summary:     ReviewSummary{Body: summaryBody, Fingerprint: fingerprintHash(summaryText)},
		Comments:    comments,
		MarkerRegex: markerRegexV1,
		MarkerFlags: "m",
		Meta:        ReviewMeta{Schema: "goose-review-envelope/v1", Provider: provider},
	}
	if provider == "github" {
		env.Event = "COMMENT"
		concl := "neutral"
		if len(visible) == 0 && !d.gateFailedLocked() {
			concl = "success"
		} else if d.HasErrorSeverity() || d.gateFailedLocked() {
			concl = "failure"
		}
		env.Meta.CheckConclusion = &concl
	}
	if env.Comments == nil {
		env.Comments = []ReviewComment{}
	}
	s, err := JSONString(env)
	if err != nil {
		return "{}"
	}
	return s
}

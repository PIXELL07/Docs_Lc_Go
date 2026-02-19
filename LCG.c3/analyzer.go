package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/tmc/langchaingo/llms"
	"github.com/tmc/langchaingo/llms/openai"
	"github.com/tmc/langchaingo/prompts"
)

var (
	reStructured = regexp.MustCompile(`^(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})\s+\[(\w+)\]\s+(.+)$`)
	reNginx      = regexp.MustCompile(`^(\d{1,3}(?:\.\d{1,3}){3}).*\[([^\]]+)\].*"([^"]*)".*(\d{3})`)
	reNum        = regexp.MustCompile(`\d+`)
	reUUID       = regexp.MustCompile(`[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}`)
	reEmail      = regexp.MustCompile(`\b\w+@\w+\.\w+\b`)
	reIP         = regexp.MustCompile(`\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b`)
	rePath       = regexp.MustCompile(`(?:/[\w.\-]+){2,}`)
	reHex        = regexp.MustCompile(`\b0x[0-9a-fA-F]+\b`)
)

// stack traces by accumulating continuation lines into the same LogEntry.
func ParseReader(r io.Reader) ([]LogEntry, error) {
	var entries []LogEntry
	scanner := bufio.NewScanner(r)

	var pending *LogEntry

	flush := func() {
		if pending != nil {
			entries = append(entries, *pending)
			pending = nil
		}
	}

	for scanner.Scan() {
		line := scanner.Text()
		if strings.TrimSpace(line) == "" {
			continue
		}

		isContinuation := len(line) > 0 &&
			(line[0] == '\t' || line[0] == ' ' ||
				strings.HasPrefix(line, "at ") ||
				strings.HasPrefix(line, "caused by") ||
				strings.HasPrefix(line, "Caused by"))

		if isContinuation && pending != nil {
			pending.Message += "\n" + strings.TrimSpace(line)
			pending.Raw += "\n" + line
			continue
		}

		flush()
		entry := tryParseLine(line)
		pending = &entry
	}

	flush()
	return entries, scanner.Err()
}

func tryParseLine(line string) LogEntry {
	if len(line) > 0 && line[0] == '{' {
		var m map[string]interface{}
		if err := json.Unmarshal([]byte(line), &m); err == nil {
			return parseJSONLog(m, line)
		}
	}

	if m := reStructured.FindStringSubmatch(line); m != nil {
		e := LogEntry{Raw: line, Level: m[2], Message: m[3]}
		if t, err := time.Parse("2006-01-02 15:04:05", m[1]); err == nil {
			e.Timestamp = t
		}
		return e
	}

	// Nginx/Apache access log
	if m := reNginx.FindStringSubmatch(line); m != nil {
		e := LogEntry{Raw: line, Source: m[1], Message: fmt.Sprintf("%s %s", m[3], m[4])}
		if t, err := time.Parse("02/Jan/2006:15:04:05 -0700", m[2]); err == nil {
			e.Timestamp = t
		}
		e.Level = nginxStatusToLevel(m[4])
		return e
	}

	// Unstructured fallback — zero timestamp intentional; callers must handle it
	return LogEntry{
		Level:   inferLogLevel(line),
		Message: line,
		Raw:     line,
	}
}

func parseJSONLog(data map[string]interface{}, raw string) LogEntry {
	e := LogEntry{Raw: raw}
	for _, k := range []string{"timestamp", "time", "@timestamp"} {
		if v, ok := data[k].(string); ok {
			for _, layout := range []string{time.RFC3339, time.RFC3339Nano, "2006-01-02 15:04:05"} {
				if t, err := time.Parse(layout, v); err == nil {
					e.Timestamp = t
					break
				}
			}
			if !e.Timestamp.IsZero() {
				break
			}
		}
	}
	for _, k := range []string{"level", "severity", "lvl"} {
		if v, ok := data[k].(string); ok {
			e.Level = strings.ToUpper(v)
			break
		}
	}
	for _, k := range []string{"message", "msg", "text"} {
		if v, ok := data[k].(string); ok {
			e.Message = v
			break
		}
	}
	for _, k := range []string{"source", "service", "app", "logger"} {
		if v, ok := data[k].(string); ok {
			e.Source = v
			break
		}
	}
	return e
}

func inferLogLevel(line string) string {
	lower := strings.ToLower(line)
	switch {
	case strings.Contains(lower, "fatal") || strings.Contains(lower, "panic"):
		return "FATAL"
	case strings.Contains(lower, "error"):
		return "ERROR"
	case strings.Contains(lower, "warn"):
		return "WARN"
	case strings.Contains(lower, "debug"):
		return "DEBUG"
	default:
		return "INFO"
	}
}

func nginxStatusToLevel(status string) string {
	if len(status) == 0 {
		return "INFO"
	}
	switch status[0] {
	case '5':
		return "ERROR"
	case '4':
		return "WARN"
	default:
		return "INFO"
	}
}

// normalizeErrorMessage replaces variable parts (IPs, UUIDs, numbers, etc.)
// so that identical errors with different values group into the same pattern.
func normalizeErrorMessage(msg string) string {
	s := reUUID.ReplaceAllString(msg, "{{UUID}}")
	s = reEmail.ReplaceAllString(s, "{{EMAIL}}")
	s = reIP.ReplaceAllString(s, "{{IP}}")
	s = rePath.ReplaceAllString(s, "{{PATH}}")
	s = reHex.ReplaceAllString(s, "{{HEX}}")
	s = reNum.ReplaceAllString(s, "{{N}}")
	return s
}

// keeping AI prompts tidy when a stack trace is attached.
func firstLine(s string) string {
	if i := strings.Index(s, "\n"); i != -1 {
		return s[:i] + " […]"
	}
	return s
}

type LogAnalyzer struct {
	llm llms.Model
}

func NewLogAnalyzer() (*LogAnalyzer, error) {
	llm, err := openai.New()
	if err != nil {
		return nil, fmt.Errorf("creating LLM: %w", err)
	}
	return &LogAnalyzer{llm: llm}, nil
}

func (la *LogAnalyzer) AnalyzeLogs(entries []LogEntry) (*LogAnalysis, error) {
	if len(entries) == 0 {
		return &LogAnalysis{}, nil
	}

	analysis := &LogAnalysis{TotalEntries: len(entries)}

	// Establish time range from entries that actually have timestamps
	for _, e := range entries {
		if !e.Timestamp.IsZero() {
			if analysis.TimeRange.Start.IsZero() || e.Timestamp.Before(analysis.TimeRange.Start) {
				analysis.TimeRange.Start = e.Timestamp
			}
			if e.Timestamp.After(analysis.TimeRange.End) {
				analysis.TimeRange.End = e.Timestamp
			}
		}
	}

	var errorMessages []string
	for _, e := range entries {
		switch strings.ToUpper(e.Level) {
		case "ERROR", "FATAL":
			analysis.ErrorCount++
			errorMessages = append(errorMessages, e.Message)
		case "WARN", "WARNING":
			analysis.WarningCount++
		}
	}

	analysis.TopErrors = findErrorPatterns(errorMessages)
	analysis.ErrorRates = computeErrorRates(entries)

	if err := la.performAIAnalysis(entries, analysis); err != nil {
		return nil, fmt.Errorf("AI analysis failed: %w", err)
	}

	return analysis, nil
}

func computeErrorRates(entries []LogEntry) []ErrorRate {
	type bucket struct{ errors, total int }
	buckets := make(map[time.Time]*bucket)

	for _, e := range entries {
		if e.Timestamp.IsZero() {
			continue
		}
		key := e.Timestamp.Truncate(time.Minute)
		if buckets[key] == nil {
			buckets[key] = &bucket{}
		}
		buckets[key].total++
		lvl := strings.ToUpper(e.Level)
		if lvl == "ERROR" || lvl == "FATAL" {
			buckets[key].errors++
		}
	}

	var rates []ErrorRate
	for k, v := range buckets {
		rates = append(rates, ErrorRate{Bucket: k, ErrorCount: v.errors, TotalCount: v.total})
	}
	sort.Slice(rates, func(i, j int) bool { return rates[i].Bucket.Before(rates[j].Bucket) })
	return rates
}

func findErrorPatterns(messages []string) []ErrorPattern {
	counts := make(map[string]int)
	examples := make(map[string]string)

	for _, msg := range messages {
		p := normalizeErrorMessage(msg)
		counts[p]++
		if examples[p] == "" {
			examples[p] = msg
		}
	}

	type kv struct {
		p string
		n int
	}
	var sorted []kv
	for k, v := range counts {
		sorted = append(sorted, kv{k, v})
	}
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].n > sorted[j].n })

	var result []ErrorPattern
	for i, item := range sorted {
		if i >= topPatternLimit {
			break
		}
		result = append(result, ErrorPattern{
			Pattern: item.p,
			Count:   item.n,
			Example: examples[item.p],
		})
	}
	return result
}

var analysisTemplate = prompts.NewPromptTemplate(`
You are an expert SRE analyzing application logs. Based on the data below, identify anomalies and provide concrete recommendations.

## Summary
- Total entries : {{.total_entries}}
- Errors        : {{.error_count}}
- Warnings      : {{.warning_count}}
- Time range    : {{.time_range}}

## Error Rate by Minute (top spikes)
{{.error_rates}}

## Top Error Patterns
{{.top_errors}}

## Recent Log Sample (last {{.sample_size}} entries)
{{.sample}}

Respond ONLY with valid JSON in this exact shape:
{
  "anomalies": [
    {
      "type": "error_spike|performance|security|other",
      "description": "What was detected",
      "severity": "critical|high|medium|low",
      "examples": ["example log line"]
    }
  ],
  "recommendations": [
    "Specific, actionable recommendation"
  ]
}`, []string{
	"total_entries", "error_count", "warning_count", "time_range",
	"error_rates", "top_errors", "sample", "sample_size",
})

func (la *LogAnalyzer) performAIAnalysis(entries []LogEntry, analysis *LogAnalysis) error {
	n := aiSampleSize
	if len(entries) < n {
		n = len(entries)
	}
	sample := entries[len(entries)-n:]

	var sampleLines strings.Builder
	for _, e := range sample {
		ts := "no-timestamp"
		if !e.Timestamp.IsZero() {
			ts = e.Timestamp.Format(time.RFC3339)
		}
		fmt.Fprintf(&sampleLines, "%s [%s] %s\n", ts, e.Level, firstLine(e.Message))
	}

	var errorRateLines strings.Builder
	shown := 0
	for _, r := range analysis.ErrorRates {
		if r.ErrorCount == 0 {
			continue
		}
		fmt.Fprintf(&errorRateLines, "%s — errors: %d / total: %d\n",
			r.Bucket.Format("15:04"), r.ErrorCount, r.TotalCount)
		shown++
		if shown >= 20 {
			break
		}
	}
	if shown == 0 {
		errorRateLines.WriteString("(no errors detected)\n")
	}

	var topErrorLines strings.Builder
	for i, p := range analysis.TopErrors {
		if i >= 5 {
			break
		}
		fmt.Fprintf(&topErrorLines, "%d. [%dx] %s\n    e.g.: %s\n", i+1, p.Count, p.Pattern, p.Example)
	}

	timeRange := "unknown"
	if !analysis.TimeRange.Start.IsZero() {
		timeRange = fmt.Sprintf("%s → %s",
			analysis.TimeRange.Start.Format(time.RFC3339),
			analysis.TimeRange.End.Format(time.RFC3339))
	}

	prompt, err := analysisTemplate.Format(map[string]any{
		"total_entries": analysis.TotalEntries,
		"error_count":   analysis.ErrorCount,
		"warning_count": analysis.WarningCount,
		"time_range":    timeRange,
		"error_rates":   errorRateLines.String(),
		"top_errors":    topErrorLines.String(),
		"sample":        sampleLines.String(),
		"sample_size":   n,
	})
	if err != nil {
		return fmt.Errorf("formatting prompt: %w", err)
	}

	ctx := context.Background()
	response, err := la.llm.GenerateContent(ctx, []llms.MessageContent{
		llms.TextParts(llms.ChatMessageTypeHuman, prompt),
	}, llms.WithJSONMode())
	if err != nil {
		return fmt.Errorf("calling LLM: %w", err)
	}

	raw := response.Choices[0].Content
	raw = strings.TrimPrefix(strings.TrimSpace(raw), "```json")
	raw = strings.TrimSuffix(raw, "```")

	var aiResult struct {
		Anomalies       []Anomaly `json:"anomalies"`
		Recommendations []string  `json:"recommendations"`
	}
	if err := json.Unmarshal([]byte(raw), &aiResult); err != nil {
		return fmt.Errorf("parsing AI response: %w (raw: %.200s)", err, raw)
	}

	analysis.Anomalies = aiResult.Anomalies
	analysis.Recommendations = aiResult.Recommendations
	return nil
}

// PrintReport prints a human-readable summary of a LogAnalysis to stdout.
func PrintReport(a *LogAnalysis) {
	fmt.Println("📊 Log Analysis Report")
	fmt.Println("======================")
	fmt.Println()

	fmt.Println("📈 Summary")
	fmt.Printf("  Total entries : %d\n", a.TotalEntries)
	fmt.Printf("  Errors        : %d\n", a.ErrorCount)
	fmt.Printf("  Warnings      : %d\n", a.WarningCount)
	if !a.TimeRange.Start.IsZero() {
		fmt.Printf("  Time range    : %s → %s\n",
			a.TimeRange.Start.Format("2006-01-02 15:04:05"),
			a.TimeRange.End.Format("2006-01-02 15:04:05"))
	}
	fmt.Println()

	if len(a.ErrorRates) > 0 {
		fmt.Println("📉 Error Rate (top 5 spiky minutes)")
		spiky := make([]ErrorRate, len(a.ErrorRates))
		copy(spiky, a.ErrorRates)
		sort.Slice(spiky, func(i, j int) bool { return spiky[i].ErrorCount > spiky[j].ErrorCount })
		for i, r := range spiky {
			if i >= 5 || r.ErrorCount == 0 {
				break
			}
			pct := 0.0
			if r.TotalCount > 0 {
				pct = float64(r.ErrorCount) / float64(r.TotalCount) * 100
			}
			fmt.Printf("  %s  %d errors  (%.0f%% of traffic)\n",
				r.Bucket.Format("15:04"), r.ErrorCount, pct)
		}
		fmt.Println()
	}

	if len(a.TopErrors) > 0 {
		fmt.Println("🔴 Top Error Patterns")
		for i, p := range a.TopErrors {
			if i >= reportPatternShow {
				break
			}
			fmt.Printf("  %d. [%dx] %s\n", i+1, p.Count, p.Pattern)
			fmt.Printf("     e.g.: %s\n", p.Example)
		}
		fmt.Println()
	}

	if len(a.Anomalies) > 0 {
		fmt.Println("⚠️  Detected Anomalies")
		for _, an := range a.Anomalies {
			fmt.Printf("  %s [%s] %s — %s\n", severityIcon(an.Severity), an.Severity, an.Type, an.Description)
		}
		fmt.Println()
	}

	if len(a.Recommendations) > 0 {
		fmt.Println("💡 Recommendations")
		for i, r := range a.Recommendations {
			fmt.Printf("  %d. %s\n", i+1, r)
		}
		fmt.Println()
	}
}

func severityIcon(s string) string {
	switch strings.ToLower(s) {
	case "critical":
		return "🚨"
	case "high":
		return "🔴"
	case "medium":
		return "🟡"
	default:
		return "🟢"
	}
}

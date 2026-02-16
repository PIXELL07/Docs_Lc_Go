package main

import (
	"bufio"
	//"context"
	"encoding/json"
	//"flag"
	"fmt"
	//"log"
	"os"
	"regexp"

	//"sort"
	"strings"
	"time"

	"github.com/tmc/langchaingo/llms"
	"github.com/tmc/langchaingo/llms/openai"
)

type LogEntry struct {
	Timestamp time.Time `json:"timestamp"`
	Level     string    `json:"level"`
	Message   string    `json:"message"`
	Source    string    `json:"source"`
	Raw       string    `json:"raw"`
}

type LogAnalysis struct {
	TotalEntries    int            `json:"total_entries"`
	ErrorCount      int            `json:"error_count"`
	WarningCount    int            `json:"warning_count"`
	TopErrors       []ErrorPattern `json:"top_errors"`
	TimeRange       TimeRange      `json:"time_range"`
	Recommendations []string       `json:"recommendations"`
	Anomalies       []Anomaly      `json:"anomalies"`
}

type ErrorPattern struct {
	Pattern string `json:"pattern"`
	Count   int    `json:"count"`
	Example string `json:"example"`
}

type TimeRange struct {
	Start time.Time `json:"start"`
	End   time.Time `json:"end"`
}

type Anomaly struct {
	Type        string   `json:"type"`
	Description string   `json:"description"`
	Severity    string   `json:"severity"`
	Examples    []string `json:"examples"`
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

func (la *LogAnalyzer) ParseLogFile(filename string) ([]LogEntry, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, fmt.Errorf("opening file: %w", err)
	}
	defer file.Close()

	var entries []LogEntry
	scanner := bufio.NewScanner(file)

	// Common log patterns
	patterns := []*regexp.Regexp{
		// JSON logs
		regexp.MustCompile(`^\{.*\}$`),
		// Standard format: 2023-01-01 12:00:00 [ERROR] message
		regexp.MustCompile(`^(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})\s+\[(\w+)\]\s+(.+)$`),
		// Nginx/Apache format
		regexp.MustCompile(`^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}).*\[([^\]]+)\].*"([^"]*)".*(\d{3})`),
	}

	for scanner.Scan() {
		line := scanner.Text()
		if strings.TrimSpace(line) == "" {
			continue
		}

		entry := LogEntry{Raw: line}

		// Try JSON first
		if line[0] == '{' {
			var jsonEntry map[string]interface{}
			if err := json.Unmarshal([]byte(line), &jsonEntry); err == nil {
				entry = parseJSONLog(jsonEntry, line)
				entries = append(entries, entry)
				continue
			}
		}

		// Try structured patterns
		for _, pattern := range patterns[1:] {
			if matches := pattern.FindStringSubmatch(line); matches != nil {
				entry = parseStructuredLog(matches, line)
				break
			}
		}

		// Fallback: treat as unstructured
		if entry.Timestamp.IsZero() {
			entry = LogEntry{
				Timestamp: time.Now(), // Use current time as fallback
				Level:     inferLogLevel(line),
				Message:   line,
				Raw:       line,
			}
		}

		entries = append(entries, entry)
	}

	return entries, scanner.Err()
}

func parseJSONLog(data map[string]interface{}, raw string) LogEntry {
	entry := LogEntry{Raw: raw}

	if ts, ok := data["timestamp"].(string); ok {
		if t, err := time.Parse(time.RFC3339, ts); err == nil {
			entry.Timestamp = t
		}
	}

	if level, ok := data["level"].(string); ok {
		entry.Level = level
	}

	if msg, ok := data["message"].(string); ok {
		entry.Message = msg
	}

	if src, ok := data["source"].(string); ok {
		entry.Source = src
	}

	return entry
}

func parseStructuredLog(matches []string, raw string) LogEntry {
	entry := LogEntry{Raw: raw}

	if len(matches) >= 4 {
		if t, err := time.Parse("2006-01-02 15:04:05", matches[1]); err == nil {
			entry.Timestamp = t
		}
		entry.Level = matches[2]
		entry.Message = matches[3]
	}

	return entry
}

func inferLogLevel(line string) string {
	lower := strings.ToLower(line)
	switch {
	case strings.Contains(lower, "error") || strings.Contains(lower, "fatal"):
		return "ERROR"
	case strings.Contains(lower, "warn"):
		return "WARN"
	case strings.Contains(lower, "debug"):
		return "DEBUG"
	default:
		return "INFO"
	}
}

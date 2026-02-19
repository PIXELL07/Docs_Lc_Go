package main

import "time"

const (
	aiSampleSize      = 50
	topPatternLimit   = 10
	reportPatternShow = 5
	watchInterval     = 30 * time.Second
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
	ErrorRates      []ErrorRate    `json:"error_rates"`
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

// ErrorRate is a per-minute bucket of error vs. total log volume.
// Used to surface spikes to both the report and the AI prompt.
type ErrorRate struct {
	Bucket     time.Time `json:"bucket"`
	ErrorCount int       `json:"error_count"`
	TotalCount int       `json:"total_count"`
}

type Anomaly struct {
	Type        string   `json:"type"`
	Description string   `json:"description"`
	Severity    string   `json:"severity"`
	Examples    []string `json:"examples"`
}

// MonitoringThresholds controls when LogMonitor fires an alert.
type MonitoringThresholds struct {
	ErrorsPerMinute   int
	CriticalKeywords  []string
	ResponseTimeLimit time.Duration
}

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
)

type SlackAlert struct {
	Text string `json:"text"`
}

func (lm *LogMonitor) sendSlackAlert(message string, webhookURL string) error {
	alert := SlackAlert{Text: fmt.Sprintf("Log Alert: %s", message)}

	jsonData, err := json.Marshal(alert)
	if err != nil {
		return err
	}

	resp, err := http.Post(webhookURL, "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	return nil
}

// Prometheus metrics
type MetricsCollector struct {
	errorCount   int
	warningCount int
}

func (mc *MetricsCollector) UpdateFromAnalysis(analysis *LogAnalysis) {
	mc.errorCount += analysis.ErrorCount
	mc.warningCount += analysis.WarningCount
}

// Export to Prometheus format
func (mc *MetricsCollector) PrometheusMetrics() string {
	return fmt.Sprintf(`
# HELP log_errors_total Total number of error log entries
# TYPE log_errors_total counter
log_errors_total %d

# HELP log_warnings_total Total number of warning log entries  
# TYPE log_warnings_total counter
log_warnings_total %d
`, mc.errorCount, mc.warningCount)
}

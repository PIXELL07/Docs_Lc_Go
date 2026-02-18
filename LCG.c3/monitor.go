package main

import (
	"context"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/tmc/langchaingo/chains"
	"github.com/tmc/langchaingo/prompts"
)

type LogMonitor struct {
	analyzer   *LogAnalyzer
	watcher    *fsnotify.Watcher
	alertChain chains.Chain
	thresholds MonitoringThresholds
}

type MonitoringThresholds struct {
	ErrorsPerMinute   int
	CriticalKeywords  []string
	ResponseTimeLimit time.Duration
}

func NewLogMonitor(analyzer *LogAnalyzer) (*LogMonitor, error) {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, err
	}

	// Create alert chain for notifications
	alertChain := chains.NewLLMChain(analyzer.llm, prompts.NewPromptTemplate(`
Generate a concise alert message for this log analysis:

{{.analysis}}

Format as: [SEVERITY] Brief description - Action needed
Keep under 140 characters.`, []string{"analysis"}))

	return &LogMonitor{
		analyzer:   analyzer,
		watcher:    watcher,
		alertChain: alertChain,
		thresholds: MonitoringThresholds{
			ErrorsPerMinute:   10,
			CriticalKeywords:  []string{"fatal", "out of memory", "database down"},
			ResponseTimeLimit: 5 * time.Second,
		},
	}, nil
}

func (lm *LogMonitor) Start(filename string) error {
	err := lm.watcher.Add(filename)
	if err != nil {
		return err
	}

	fmt.Printf("🚨 Monitoring %s for critical issues...\n", filename)

	for {
		select {
		case event, ok := <-lm.watcher.Events:
			if !ok {
				return nil
			}
			if event.Op&fsnotify.Write == fsnotify.Write {
				go lm.checkForAlerts(filename)
			}
		case err, ok := <-lm.watcher.Errors:
			if !ok {
				return nil
			}
			log.Printf("Watcher error: %v", err)
		}
	}
}

func (lm *LogMonitor) checkForAlerts(filename string) {
	// Read last N lines and check for critical issues
	entries, err := lm.analyzer.ParseLogFile(filename)
	if err != nil {
		log.Printf("Error parsing file: %v", err)
		return
	}

	// Check recent entries (last minute)
	recent := lm.getRecentEntries(entries, time.Minute)
	if lm.shouldAlert(recent) {
		analysis, err := lm.analyzer.AnalyzeLogs(recent)
		if err != nil {
			log.Printf("Error analyzing logs: %v", err)
			return
		}

		alert, err := chains.Run(context.Background(), lm.alertChain,
			fmt.Sprintf("Analysis: %+v", analysis))
		if err != nil {
			log.Printf("Error generating alert: %v", err)
			return
		}

		fmt.Printf("🚨 ALERT: %s\n", alert)
		// Here you would send to Slack, email, etc.
	}
}

func (lm *LogMonitor) getRecentEntries(entries []LogEntry, duration time.Duration) []LogEntry {
	cutoff := time.Now().Add(-duration)
	var recent []LogEntry

	for i := len(entries) - 1; i >= 0; i-- {
		if entries[i].Timestamp.Before(cutoff) {
			break
		}
		recent = append([]LogEntry{entries[i]}, recent...)
	}

	return recent
}

func (lm *LogMonitor) shouldAlert(entries []LogEntry) bool {
	errorCount := 0
	for _, entry := range entries {
		if entry.Level == "ERROR" || entry.Level == "FATAL" {
			errorCount++
		}

		// Check for critical keywords
		for _, keyword := range lm.thresholds.CriticalKeywords {
			if strings.Contains(strings.ToLower(entry.Message), keyword) {
				return true
			}
		}
	}

	return errorCount >= lm.thresholds.ErrorsPerMinute
}

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"strings"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/tmc/langchaingo/chains"
	"github.com/tmc/langchaingo/prompts"
)

// LogMonitor watches a file with fsnotify and fires AI-generated alerts
// whenever MonitoringThresholds are breached. It reuses LogAnalyzer for all
// parsing and analysis so both components stay in sync.
type LogMonitor struct {
	analyzer   *LogAnalyzer
	watcher    *fsnotify.Watcher
	alertChain chains.Chain
	thresholds MonitoringThresholds

	// lastOffset tracks how far through the file we have already read,
	// so checkForAlerts only processes new bytes on each write event.
	lastOffset int64
}

func NewLogMonitor(analyzer *LogAnalyzer) (*LogMonitor, error) {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, fmt.Errorf("creating fsnotify watcher: %w", err)
	}

	// Alert chain: condenses a full LogAnalysis into a single short message
	// suitable for Slack / PagerDuty / email.
	alertChain := chains.NewLLMChain(
		analyzer.llm,
		prompts.NewPromptTemplate(`
Generate a concise alert message for this log analysis:

{{.analysis}}

Format as: [SEVERITY] Brief description - Action needed
Keep under 140 characters.`, []string{"analysis"}),
	)

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

// Start registers filename with fsnotify and blocks, processing write events.
// Using fsnotify means we react instantly to new log lines rather than polling.
func (lm *LogMonitor) Start(filename string) error {
	// Seed offset so we only alert on content written after startup.
	if info, err := os.Stat(filename); err == nil {
		lm.lastOffset = info.Size()
	}

	if err := lm.watcher.Add(filename); err != nil {
		return fmt.Errorf("watching %s: %w", filename, err)
	}
	defer lm.watcher.Close()

	fmt.Printf("🚨 Monitoring %s for critical issues…\n", filename)

	for {
		select {
		case event, ok := <-lm.watcher.Events:
			if !ok {
				return nil
			}
			switch {
			case event.Op&fsnotify.Write == fsnotify.Write:
				go lm.checkForAlerts(filename)

			case event.Op&fsnotify.Remove == fsnotify.Remove,
				event.Op&fsnotify.Rename == fsnotify.Rename:
				// Log rotation: reset offset and re-register after the new file appears.
				fmt.Println("↩️  Log rotation detected — resetting offset")
				lm.lastOffset = 0
				time.AfterFunc(500*time.Millisecond, func() {
					_ = lm.watcher.Add(filename)
				})
			}

		case err, ok := <-lm.watcher.Errors:
			if !ok {
				return nil
			}
			log.Printf("watcher error: %v", err)
		}
	}
}

// checkForAlerts reads only the new bytes since the last event, parses them,
// and fires an alert when thresholds are breached.
func (lm *LogMonitor) checkForAlerts(filename string) {
	entries, newOffset, err := lm.readNewEntries(filename)
	if err != nil {
		log.Printf("error reading new entries: %v", err)
		return
	}
	if len(entries) == 0 {
		return
	}
	lm.lastOffset = newOffset

	recent := lm.getRecentEntries(entries, time.Minute)
	if !lm.shouldAlert(recent) {
		return
	}

	analysis, err := lm.analyzer.AnalyzeLogs(recent)
	if err != nil {
		log.Printf("error analyzing logs: %v", err)
		return
	}

	analysisJSON, _ := json.Marshal(analysis)
	alert, err := chains.Run(
		context.Background(),
		lm.alertChain,
		string(analysisJSON),
	)
	if err != nil {
		log.Printf("error generating alert: %v", err)
		return
	}

	fmt.Printf("🚨 ALERT: %s\n", strings.TrimSpace(alert))
	// TODO: forward to Slack / PagerDuty / email here
}

// readNewEntries opens filename, seeks to lastOffset, and parses only new lines.
// Returns the parsed entries and the updated file offset.
func (lm *LogMonitor) readNewEntries(filename string) ([]LogEntry, int64, error) {
	f, err := os.Open(filename)
	if err != nil {
		return nil, lm.lastOffset, fmt.Errorf("opening file: %w", err)
	}
	defer f.Close()

	if lm.lastOffset > 0 {
		if _, err := f.Seek(lm.lastOffset, io.SeekStart); err != nil {
			return nil, lm.lastOffset, fmt.Errorf("seeking: %w", err)
		}
	}

	entries, err := ParseReader(f)
	if err != nil {
		return nil, lm.lastOffset, fmt.Errorf("parsing: %w", err)
	}

	newOffset, err := f.Seek(0, io.SeekCurrent)
	if err != nil {
		return entries, lm.lastOffset, fmt.Errorf("getting offset: %w", err)
	}

	return entries, newOffset, nil
}

// getRecentEntries returns entries whose timestamp falls within duration of now.
// Entries with no timestamp are included conservatively — they may be recent.
func (lm *LogMonitor) getRecentEntries(entries []LogEntry, duration time.Duration) []LogEntry {
	cutoff := time.Now().Add(-duration)
	var recent []LogEntry
	for _, e := range entries {
		if e.Timestamp.IsZero() || !e.Timestamp.Before(cutoff) {
			recent = append(recent, e)
		}
	}
	return recent
}

// shouldAlert returns true when the error count or a critical keyword threshold
// is hit within the supplied window of entries.
func (lm *LogMonitor) shouldAlert(entries []LogEntry) bool {
	errorCount := 0
	for _, e := range entries {
		lvl := strings.ToUpper(e.Level)
		if lvl == "ERROR" || lvl == "FATAL" {
			errorCount++
		}
		lower := strings.ToLower(e.Message)
		for _, kw := range lm.thresholds.CriticalKeywords {
			if strings.Contains(lower, kw) {
				return true
			}
		}
	}
	return errorCount >= lm.thresholds.ErrorsPerMinute
}

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
)

func main() {
	var (
		file    = flag.String("file", "-", "Log file to analyze (use - for stdin)")
		output  = flag.String("output", "", "Output file for JSON report")
		monitor = flag.Bool("monitor", false, "Watch file with fsnotify and alert on threshold breaches")
	)
	flag.Parse()

	analyzer, err := NewLogAnalyzer()
	if err != nil {
		log.Fatal(err)
	}

	if *monitor {
		if *file == "-" {
			log.Fatal("-monitor requires a real file path, not stdin")
		}
		lm, err := NewLogMonitor(analyzer)
		if err != nil {
			log.Fatal(err)
		}
		if err := lm.Start(*file); err != nil {
			log.Fatal(err)
		}
		return
	}

	if err := analyzeFile(analyzer, *file, *output); err != nil {
		log.Fatal(err)
	}
}

// openInput returns a ReadCloser for the given path, or stdin if path is "-".
func openInput(path string) (io.ReadCloser, error) {
	if path == "-" {
		return io.NopCloser(os.Stdin), nil
	}
	return os.Open(path)
}

// analyzeFile is the one-shot analysis path: parse → analyze → report → optionally write JSON.
func analyzeFile(analyzer *LogAnalyzer, filename, outputFile string) error {
	fmt.Printf("🔍 Analyzing %s…\n", filename)

	rc, err := openInput(filename)
	if err != nil {
		return fmt.Errorf("opening input: %w", err)
	}
	defer rc.Close()

	entries, err := ParseReader(rc)
	if err != nil {
		return fmt.Errorf("parsing log: %w", err)
	}
	fmt.Printf("   Parsed %d entries\n", len(entries))

	analysis, err := analyzer.AnalyzeLogs(entries)
	if err != nil {
		return fmt.Errorf("analyzing logs: %w", err)
	}

	PrintReport(analysis)

	if outputFile != "" {
		data, err := json.MarshalIndent(analysis, "", "  ")
		if err != nil {
			return fmt.Errorf("marshaling report: %w", err)
		}
		if err := os.WriteFile(outputFile, data, 0o644); err != nil {
			return fmt.Errorf("writing report: %w", err)
		}
		fmt.Printf("📄 JSON report saved to %s\n", outputFile)
	}
	return nil
}

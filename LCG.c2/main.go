package main

import (
	"context"
	"flag"
	"fmt"
	"go/parser"
	"go/token"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/tmc/langchaingo/llms"
	"github.com/tmc/langchaingo/llms/openai"
	"github.com/tmc/langchaingo/prompts"
)

type CodeReviewer struct {
	llm      llms.Model
	template *prompts.PromptTemplate
}

func NewCodeReviewer() (*CodeReviewer, error) {
	llm, err := openai.New()
	if err != nil {
		return nil, err
	}

	template := prompts.NewPromptTemplate(`
	You are a code reviewer. Please review the following Go code and provide feedback on style, correctness, and potential improvements.`,
		[]string{"code", "filename"})

	return &CodeReviewer{
		llm:      llm,
		template: &template,
	}, nil
}

func (cr *CodeReviewer) ReviewFile(filename string) error {
	content, err := os.ReadFile(filename)
	if err != nil {
		return fmt.Errorf("reading file: %w", err)
	}

	// Parse Go code to ensure it's valid
	fset := token.NewFileSet()
	_, err = parser.ParseFile(fset, filename, content, parser.ParseComments)
	if err != nil {
		return fmt.Errorf("parsing Go file: %w", err)
	}

	prompt, err := cr.template.Format(map[string]any{
		"code":     string(content),
		"filename": filename,
	})
	if err != nil {
		return fmt.Errorf("formatting prompt: %w", err)
	}

	ctx := context.Background()
	response, err := cr.llm.GenerateContent(ctx, []llms.MessageContent{
		llms.TextParts(llms.ChatMessageTypeHuman, prompt),
	})
	if err != nil {
		return fmt.Errorf("generating review: %w", err)
	}

	fmt.Printf("\n=== Review for %s ===\n", filename)
	fmt.Println(strings.Repeat("=", 80))
	fmt.Println(response.Choices[0].Content)
	fmt.Println(strings.Repeat("=", 80))

	return nil
}

func main() {
	var (
		file = flag.String("file", "", "Go file to review")
		dir  = flag.String("dir", "", "Directory to review (all .go files)")
		git  = flag.Bool("git", false, "Review files changed in git working directory")
	)
	flag.Parse()

	reviewer, err := NewCodeReviewer()
	if err != nil {
		log.Fatal(err)
	}

	switch {
	case *file != "":
		if err := reviewer.ReviewFile(*file); err != nil {
			log.Fatal(err)
		}
	case *dir != "":
		if err := reviewDirectory(reviewer, *dir); err != nil {
			log.Fatal(err)
		}
	case *git:
		if err := reviewGitChanges(reviewer); err != nil {
			log.Fatal(err)
		}
	default:
		fmt.Println("Usage:")
		fmt.Println("  code-reviewer -file=main.go")
		fmt.Println("  code-reviewer -dir=./pkg")
		fmt.Println("  code-reviewer -git")
		os.Exit(1)
	}
}

func reviewDirectory(reviewer *CodeReviewer, dir string) error {
	return filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if strings.HasSuffix(path, ".go") && !strings.Contains(path, "vendor/") {
			return reviewer.ReviewFile(path)
		}
		return nil
	})
}

func reviewGitChanges(reviewer *CodeReviewer) error {
	// This is a simplified version - you'd want to use a proper git library
	cmd := exec.Command("git", "diff", "--name-only", "HEAD")
	output, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("getting git changes: %w", err)
	}

	files := strings.Split(strings.TrimSpace(string(output)), "\n")
	for _, file := range files {
		if strings.HasSuffix(file, ".go") && file != "" {
			if err := reviewer.ReviewFile(file); err != nil {
				log.Printf("Error reviewing %s: %v", file, err)
			}
		}
	}
	return nil
}

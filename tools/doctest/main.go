// Package main provides executable documentation testing tool that validates code blocks in markdown files.
package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

var (
	ErrProjectRootNotFound = errors.New("could not determine project root")
	errRegionNotFound      = errors.New("region not found")
)

// CodeBlock represents an executable code block from markdown
type CodeBlock struct {
	Language string
	Code     string
	Line     int
	Execute  bool
	Expect   string
	// Setup marks this block as a setup block (runs before all exec blocks).
	Setup bool
	// Teardown marks this block as a teardown block (runs after all exec blocks, always).
	Teardown bool
	// Source links this block to a source file region for content verification.
	Source *SourceDirective
}

// SourceDirective links a code block to a region in a source file for verification.
type SourceDirective struct {
	FilePath   string // Resolved absolute path to source file
	RegionName string // Region name within the file
	Line       int    // Line in markdown where directive appears
}

// EnvDirective represents a <!-- doctest:env KEY=VALUE --> directive
type EnvDirective struct {
	Key   string
	Value string
	Line  int
}

// TestResult represents the result of executing a code block
type TestResult struct {
	Block    CodeBlock
	File     string
	Success  bool
	Output   string
	Error    string
	Duration time.Duration
}

func main() {
	if len(os.Args) < 2 {
		_, _ = fmt.Fprintf(os.Stderr, "Usage: %s [--sync] <markdown-file> [<markdown-file>...]\n", os.Args[0])
		os.Exit(1)
	}

	syncMode := false
	var files []string
	for _, arg := range os.Args[1:] {
		if arg == "--sync" {
			syncMode = true
		} else {
			files = append(files, arg)
		}
	}

	if len(files) == 0 {
		_, _ = fmt.Fprintf(os.Stderr, "Usage: %s [--sync] <markdown-file> [<markdown-file>...]\n", os.Args[0])
		os.Exit(1)
	}

	if syncMode {
		hasError := false
		for _, file := range files {
			n, err := syncMarkdownFile(file)
			if err != nil {
				_, _ = fmt.Fprintf(os.Stderr, "Error syncing %s: %v\n", file, err)
				hasError = true
				continue
			}
			if n > 0 {
				fmt.Printf("Synced %d code block(s) in %s\n", n, file)
			} else {
				fmt.Printf("No changes needed in %s\n", file)
			}
		}
		if hasError {
			os.Exit(1)
		}
		return
	}

	totalTests := 0
	totalPassed := 0
	totalFailed := 0

	for _, file := range files {
		fmt.Printf("\U0001f4c4 Testing: %s\n", file)
		fmt.Println(strings.Repeat("=", 60))

		results, err := testMarkdownFile(file)
		if err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "Error testing %s: %v\n", file, err)

			continue
		}

		for _, result := range results {
			totalTests++

			if result.Success {
				totalPassed++
				fmt.Printf("\u2705 Line %d: %s (%v)\n", result.Block.Line, result.Block.Language, result.Duration)
			} else {
				totalFailed++
				fmt.Printf("\u274c Line %d: %s\n", result.Block.Line, result.Block.Language)
				fmt.Printf("   Error: %s\n", result.Error)
				if result.Output != "" {
					fmt.Printf("   Output:\n%s\n", indentOutput(result.Output))
				}
			}
		}

		fmt.Println()
	}

	fmt.Println(strings.Repeat("=", 60))
	fmt.Printf("\U0001f4ca Results: %d total, %d passed, %d failed\n", totalTests, totalPassed, totalFailed)
	fmt.Println(strings.Repeat("=", 60))

	if totalFailed > 0 {
		os.Exit(1)
	}
}

func testMarkdownFile(path string) ([]TestResult, error) {
	// #nosec G304 - Reading user-specified markdown files is the intended functionality of this tool
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read file: %w", err)
	}

	blocks, envDirectives := extractCodeBlocks(string(content), path)

	// Verify source-linked blocks first
	sourceResults := verifySourceBlocks(blocks, path)

	// Separate setup, teardown, and exec blocks
	var setupBlock *CodeBlock
	var teardownBlock *CodeBlock
	var execBlocks []CodeBlock

	for i := range blocks {
		switch {
		case blocks[i].Setup:
			setupBlock = &blocks[i]
		case blocks[i].Teardown:
			teardownBlock = &blocks[i]
		case blocks[i].Execute:
			execBlocks = append(execBlocks, blocks[i])
		}
	}

	// If there are setup/teardown blocks, use session-based execution
	if setupBlock != nil || teardownBlock != nil {
		execResults, err := executeWithSession(path, setupBlock, teardownBlock, execBlocks, envDirectives)
		if err != nil {
			return sourceResults, err
		}
		return append(sourceResults, execResults...), nil
	}

	// Otherwise, use simple per-block execution (original behavior)
	for _, block := range execBlocks {
		result := executeCodeBlock(path, block)
		sourceResults = append(sourceResults, result)
	}

	return sourceResults, nil
}

// verifySourceBlocks checks that code blocks with source directives match their source regions.
func verifySourceBlocks(blocks []CodeBlock, file string) []TestResult {
	results := make([]TestResult, 0, len(blocks))
	for _, block := range blocks {
		if block.Source == nil {
			continue
		}

		result := TestResult{
			Block:   block,
			File:    file,
			Success: false,
		}

		start := time.Now()

		regionCode, err := extractRegion(block.Source.FilePath, block.Source.RegionName)
		if err != nil {
			result.Error = fmt.Sprintf("source %s#%s: %v", block.Source.FilePath, block.Source.RegionName, err)
			result.Duration = time.Since(start)
			results = append(results, result)
			continue
		}

		expected := normalizeCode(regionCode)
		actual := normalizeCode(block.Code)

		if expected != actual {
			result.Error = fmt.Sprintf(
				"source mismatch: %s#%s\n   Run: doctest --sync %s\n\n--- source (%s#%s)\n+++ markdown (%s:%d)\n%s",
				filepath.Base(block.Source.FilePath), block.Source.RegionName,
				file,
				filepath.Base(block.Source.FilePath), block.Source.RegionName,
				file, block.Line,
				simpleDiff(expected, actual),
			)
			result.Duration = time.Since(start)
			results = append(results, result)
			continue
		}

		result.Success = true
		result.Duration = time.Since(start)
		results = append(results, result)
	}
	return results
}

// extractRegion reads a source file and extracts the content between region markers.
// Markers are line comments: "// region: <name>" and "// endregion: <name>".
// The markers themselves are excluded. Leading common indentation is stripped.
func extractRegion(filePath string, regionName string) (string, error) {
	// #nosec G304 - Reading user-specified source files is the intended functionality of this tool
	content, err := os.ReadFile(filePath)
	if err != nil {
		return "", fmt.Errorf("read source file: %w", err)
	}

	lines := strings.Split(string(content), "\n")
	startMarker := "// region: " + regionName
	endMarker := "// endregion: " + regionName

	var regionLines []string
	inRegion := false

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == startMarker {
			inRegion = true
			continue
		}
		if trimmed == endMarker {
			break
		}
		if inRegion {
			regionLines = append(regionLines, line)
		}
	}

	if !inRegion {
		return "", fmt.Errorf("%w: %q in %s", errRegionNotFound, regionName, filepath.Base(filePath))
	}

	// Strip common leading indentation (tabs)
	regionLines = dedent(regionLines)

	return strings.Join(regionLines, "\n"), nil
}

// dedent removes the common leading whitespace from all non-empty lines.
func dedent(lines []string) []string {
	// Find minimum indentation across non-empty lines
	minIndent := -1
	for _, line := range lines {
		if strings.TrimSpace(line) == "" {
			continue
		}
		indent := len(line) - len(strings.TrimLeft(line, " \t"))
		if minIndent < 0 || indent < minIndent {
			minIndent = indent
		}
	}

	if minIndent <= 0 {
		return lines
	}

	result := make([]string, len(lines))
	for i, line := range lines {
		if len(line) >= minIndent {
			result[i] = line[minIndent:]
		} else {
			result[i] = line
		}
	}
	return result
}

// normalizeCode trims trailing whitespace per line and leading/trailing blank lines.
func normalizeCode(s string) string {
	lines := strings.Split(s, "\n")

	// Trim trailing whitespace per line
	for i, line := range lines {
		lines[i] = strings.TrimRight(line, " \t")
	}

	// Trim leading blank lines
	for len(lines) > 0 && strings.TrimSpace(lines[0]) == "" {
		lines = lines[1:]
	}
	// Trim trailing blank lines
	for len(lines) > 0 && strings.TrimSpace(lines[len(lines)-1]) == "" {
		lines = lines[:len(lines)-1]
	}

	return strings.Join(lines, "\n")
}

// simpleDiff produces a basic line-by-line diff between two strings.
func simpleDiff(expected, actual string) string {
	expectedLines := strings.Split(expected, "\n")
	actualLines := strings.Split(actual, "\n")

	var buf strings.Builder
	maxLines := max(len(expectedLines), len(actualLines))

	for i := range maxLines {
		var eLine, aLine string
		if i < len(expectedLines) {
			eLine = expectedLines[i]
		}
		if i < len(actualLines) {
			aLine = actualLines[i]
		}
		if eLine != aLine {
			if i < len(expectedLines) {
				fmt.Fprintf(&buf, "  -%s\n", eLine)
			}
			if i < len(actualLines) {
				fmt.Fprintf(&buf, "  +%s\n", aLine)
			}
		} else {
			fmt.Fprintf(&buf, "   %s\n", eLine)
		}
	}
	return buf.String()
}

// syncMarkdownFile updates code blocks in a markdown file to match their source regions.
// Returns the number of blocks that were updated.
func syncMarkdownFile(path string) (int, error) {
	// #nosec G304 - Reading user-specified markdown files is the intended functionality of this tool
	content, err := os.ReadFile(path)
	if err != nil {
		return 0, fmt.Errorf("read file: %w", err)
	}

	lines := strings.Split(string(content), "\n")
	updated := 0

	// Find source directives and their associated code blocks, then replace content.
	// We process from bottom to top so line numbers remain valid after replacements.
	type replacement struct {
		codeStart int // line index of first code line (after ```)
		codeEnd   int // line index of closing ```
		newCode   string
	}

	var replacements []replacement
	var pendingSource *SourceDirective

	for i, line := range lines {
		// Check for source directive
		if sd, ok := parseSourceDirective(line, path); ok {
			pendingSource = sd
			continue
		}

		// Check for code fence start when we have a pending source
		if pendingSource != nil {
			if lang, ok := strings.CutPrefix(line, "```"); ok && strings.TrimSpace(lang) != "" {
				// Found the start of the code block — find its end
				codeStart := i + 1
				for j := codeStart; j < len(lines); j++ {
					if strings.HasPrefix(lines[j], "```") {
						// Extract region content
						regionCode, err := extractRegion(pendingSource.FilePath, pendingSource.RegionName)
						if err != nil {
							_, _ = fmt.Fprintf(os.Stderr, "Warning: %v\n", err)
							break
						}

						// Check if update needed
						currentCode := normalizeCode(strings.Join(lines[codeStart:j], "\n"))
						newCode := normalizeCode(regionCode)
						if currentCode != newCode {
							replacements = append(replacements, replacement{
								codeStart: codeStart,
								codeEnd:   j,
								newCode:   newCode,
							})
						}
						break
					}
				}
				pendingSource = nil
				continue
			}

			// If we hit a non-empty, non-fence line, the source directive doesn't apply
			if strings.TrimSpace(line) != "" {
				pendingSource = nil
			}
		}
	}

	if len(replacements) == 0 {
		return 0, nil
	}

	// Apply replacements from bottom to top
	for i := len(replacements) - 1; i >= 0; i-- {
		r := replacements[i]
		newLines := strings.Split(r.newCode, "\n")
		// Replace lines[codeStart:codeEnd] with newLines
		head := lines[:r.codeStart]
		tail := lines[r.codeEnd:]
		lines = make([]string, 0, len(head)+len(newLines)+len(tail))
		lines = append(lines, head...)
		lines = append(lines, newLines...)
		lines = append(lines, tail...)
		updated++
	}

	err = os.WriteFile(path, []byte(strings.Join(lines, "\n")), 0o600)
	if err != nil {
		return 0, fmt.Errorf("write file: %w", err)
	}

	return updated, nil
}

// executeWithSession runs blocks with a shared environment file for state passing.
// Setup runs first (60s timeout), then exec blocks in order (30s each), then teardown (15s, always).
func executeWithSession(
	file string,
	setupBlock *CodeBlock,
	teardownBlock *CodeBlock,
	execBlocks []CodeBlock,
	envDirectives []EnvDirective,
) ([]TestResult, error) {
	// Create a temporary env file for state sharing between blocks
	envFile, err := os.CreateTemp("", "doctest-env-*")
	if err != nil {
		return nil, fmt.Errorf("create env file: %w", err)
	}
	envFilePath := envFile.Name()
	defer func() { _ = os.Remove(envFilePath) }()

	// Write initial env directives to the env file
	for _, env := range envDirectives {
		_, _ = fmt.Fprintf(envFile, "export %s=%s\n", env.Key, shellQuote(env.Value))
	}
	_ = envFile.Close()

	results := []TestResult{}

	// Run setup block (60s timeout)
	if setupBlock != nil {
		fmt.Printf("\U0001f527 Running setup (line %d)...\n", setupBlock.Line)
		result := executeCodeBlockWithEnvFile(file, *setupBlock, envFilePath, 60*time.Second)
		results = append(results, result)
		if !result.Success {
			// Setup failed — run teardown and return
			if teardownBlock != nil {
				fmt.Printf("\U0001f9f9 Running teardown after setup failure (line %d)...\n", teardownBlock.Line)
				tdResult := executeCodeBlockWithEnvFile(file, *teardownBlock, envFilePath, 15*time.Second)
				results = append(results, tdResult)
			}
			return results, nil
		}
	}

	// Run exec blocks in order (30s timeout each)
	for _, block := range execBlocks {
		result := executeCodeBlockWithEnvFile(file, block, envFilePath, 30*time.Second)
		results = append(results, result)
	}

	// Always run teardown (15s timeout)
	if teardownBlock != nil {
		fmt.Printf("\U0001f9f9 Running teardown (line %d)...\n", teardownBlock.Line)
		tdResult := executeCodeBlockWithEnvFile(file, *teardownBlock, envFilePath, 15*time.Second)
		results = append(results, tdResult)
	}

	return results, nil
}

// directiveState tracks pending directive flags while scanning markdown lines.
type directiveState struct {
	execNext     bool
	setupNext    bool
	teardownNext bool
	sourceNext   *SourceDirective
}

func extractCodeBlocks(content string, markdownFile string) ([]CodeBlock, []EnvDirective) {
	var blocks []CodeBlock
	var envDirectives []EnvDirective
	lines := strings.Split(content, "\n")

	inCodeBlock := false
	currentBlock := CodeBlock{}
	var currentLine int
	var ds directiveState

	for i, line := range lines {
		lineNum := i + 1

		// Inside a code block, accumulate content or close the fence.
		if inCodeBlock {
			if _, ok := strings.CutPrefix(line, "```"); ok {
				inCodeBlock = false
				if currentBlock.Language != "" {
					blocks = append(blocks, currentBlock)
				}
				currentBlock = CodeBlock{}
			} else {
				currentBlock.Code += line + "\n"
			}
			continue
		}

		// Outside a code block: check for directives or a code fence start.
		if handled := handleDirective(line, lineNum, markdownFile, &blocks, &envDirectives, &ds); handled {
			continue
		}

		// Check for code fence start.
		if lang, ok := strings.CutPrefix(line, "```"); ok {
			inCodeBlock = true
			currentLine = lineNum
			currentBlock = openCodeBlock(lang, currentLine, &ds)
		}
	}

	return blocks, envDirectives
}

// handleDirective processes a single non-fence line for doctest directives.
// Returns true if the line was consumed by a directive.
func handleDirective(line string, lineNum int, markdownFile string, blocks *[]CodeBlock, envDirectives *[]EnvDirective, ds *directiveState) bool {
	// doctest:exec
	if strings.Contains(line, "<!-- doctest:exec -->") || strings.Contains(line, "<!-- doctest:execute -->") {
		ds.execNext = true
		return true
	}

	// doctest:source
	if sd, ok := parseSourceDirective(line, markdownFile); ok {
		ds.sourceNext = sd
		return true
	}

	// doctest:setup:file
	if block, ok := handleFileDirective(line, lineNum, markdownFile, "setup"); ok {
		*blocks = append(*blocks, block)
		return true
	}

	// doctest:teardown:file
	if block, ok := handleFileDirective(line, lineNum, markdownFile, "teardown"); ok {
		*blocks = append(*blocks, block)
		return true
	}

	// doctest:setup
	if strings.Contains(line, "<!-- doctest:setup -->") {
		ds.setupNext = true
		return true
	}

	// doctest:teardown
	if strings.Contains(line, "<!-- doctest:teardown -->") {
		ds.teardownNext = true
		return true
	}

	// doctest:env KEY=VALUE
	if strings.Contains(line, "<!-- doctest:env ") {
		if env, ok := parseEnvDirective(line, lineNum); ok {
			*envDirectives = append(*envDirectives, env)
		}
		return true
	}

	return false
}

// handleFileDirective parses a setup:file or teardown:file directive and returns
// the resulting CodeBlock. The directiveType must be "setup" or "teardown".
func handleFileDirective(line string, lineNum int, markdownFile string, directiveType string) (CodeBlock, bool) {
	path, ok := parseFileDirective(line, directiveType)
	if !ok {
		return CodeBlock{}, false
	}
	resolved := resolveDirectivePath(path, markdownFile)
	// #nosec G304 - Reading user-specified files is the intended functionality of this tool
	fileContent, err := os.ReadFile(resolved)
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "Warning: could not read %s file %s: %v\n", directiveType, resolved, err)
		return CodeBlock{}, false
	}

	block := CodeBlock{
		Execute:  true,
		Language: "bash",
		Code:     string(fileContent),
		Line:     lineNum,
	}
	if directiveType == "setup" {
		block.Setup = true
	} else {
		block.Teardown = true
	}
	return block, true
}

// openCodeBlock initialises a CodeBlock for a newly opened code fence and consumes
// any pending directive flags from the state.
func openCodeBlock(lang string, lineNum int, ds *directiveState) CodeBlock {
	block := CodeBlock{Line: lineNum}

	lang = strings.TrimSpace(lang)
	parts := strings.Fields(lang)
	if len(parts) > 0 {
		block.Language = parts[0]
		for _, part := range parts[1:] {
			if part == "exec" || part == "execute" {
				block.Execute = true
			}
		}
	}

	if ds.execNext {
		block.Execute = true
		ds.execNext = false
	}
	if ds.setupNext {
		block.Setup = true
		block.Execute = true
		ds.setupNext = false
	}
	if ds.teardownNext {
		block.Teardown = true
		block.Execute = true
		ds.teardownNext = false
	}
	if ds.sourceNext != nil {
		block.Source = ds.sourceNext
		ds.sourceNext = nil
	}

	return block
}

// parseSourceDirective parses <!-- doctest:source PATH#REGION --> into a SourceDirective.
func parseSourceDirective(line string, markdownFile string) (*SourceDirective, bool) {
	const prefix = "<!-- doctest:source "

	_, after, found := strings.Cut(line, prefix)
	if !found {
		return nil, false
	}

	// Strip the closing --> comment marker
	content, found := strings.CutSuffix(after, " -->")
	if !found {
		content, found = strings.CutSuffix(after, "-->")
		if !found {
			return nil, false
		}
	}

	content = strings.TrimSpace(content)

	// Split on # to get file path and region name
	filePath, regionName, found := strings.Cut(content, "#")
	if !found {
		return nil, false
	}

	resolved := resolveDirectivePath(strings.TrimSpace(filePath), markdownFile)

	return &SourceDirective{
		FilePath:   resolved,
		RegionName: strings.TrimSpace(regionName),
	}, true
}

// parseFileDirective extracts the file path from <!-- doctest:{type}:file PATH -->
func parseFileDirective(line string, directiveType string) (string, bool) {
	prefix := "<!-- doctest:" + directiveType + ":file "
	_, after, found := strings.Cut(line, prefix)
	if !found {
		return "", false
	}

	// Strip the closing --> comment marker
	path, found := strings.CutSuffix(after, " -->")
	if !found {
		path, found = strings.CutSuffix(after, "-->")
		if !found {
			return "", false
		}
	}

	return strings.TrimSpace(path), true
}

// resolveDirectivePath resolves a directive path relative to the project root.
// If the path is absolute, it is returned as-is. Otherwise it is joined with the
// project root (found by walking up from the markdown file).
func resolveDirectivePath(path string, markdownFile string) string {
	if filepath.IsAbs(path) {
		return path
	}
	root, err := findProjectRoot(markdownFile)
	if err != nil {
		return path
	}
	return filepath.Join(root, path)
}

// parseEnvDirective extracts KEY=VALUE from <!-- doctest:env KEY=VALUE -->
func parseEnvDirective(line string, lineNum int) (EnvDirective, bool) {
	const prefix = "<!-- doctest:env "

	_, after, found := strings.Cut(line, prefix)
	if !found {
		return EnvDirective{}, false
	}

	// Strip the closing --> comment marker
	content, found := strings.CutSuffix(after, " -->")
	if !found {
		content, found = strings.CutSuffix(after, "-->")
		if !found {
			return EnvDirective{}, false
		}
	}

	kv := strings.TrimSpace(content)
	key, value, found := strings.Cut(kv, "=")
	if !found {
		return EnvDirective{}, false
	}

	return EnvDirective{
		Key:   strings.TrimSpace(key),
		Value: strings.TrimSpace(value),
		Line:  lineNum,
	}, true
}

func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "'\\''") + "'"
}

// runBashCommand executes a bash command string in the project root directory with the given timeout,
// populating the TestResult with output, duration, and success/error status.
func runBashCommand(file string, block CodeBlock, code string, timeout time.Duration) TestResult {
	result := TestResult{
		Block:   block,
		File:    file,
		Success: false,
	}

	start := time.Now()

	// Only execute bash/sh/shell blocks
	if block.Language != "bash" && block.Language != "sh" && block.Language != "shell" {
		result.Success = true
		result.Duration = time.Since(start)

		return result
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	// #nosec G204 - Executing code blocks from markdown is the intended functionality of this documentation testing tool
	cmd := exec.CommandContext(ctx, "bash", "-c", code)

	// Set working directory to project root
	projectRoot, findErr := findProjectRoot(file)
	if findErr == nil {
		cmd.Dir = projectRoot
	}

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	result.Duration = time.Since(start)
	result.Output = stdout.String()

	if err != nil {
		result.Success = false
		result.Error = fmt.Sprintf("%v\n%s", err, stderr.String())
	} else {
		result.Success = true
	}

	return result
}

func executeCodeBlock(file string, block CodeBlock) TestResult {
	return runBashCommand(file, block, strings.TrimSpace(block.Code), 30*time.Second)
}

// executeCodeBlockWithEnvFile runs a code block that sources an env file before execution.
// The block can also write to the env file to pass state to subsequent blocks.
func executeCodeBlockWithEnvFile(file string, block CodeBlock, envFilePath string, timeout time.Duration) TestResult {
	// Wrap the code to source the env file first and export DOCTEST_ENV_FILE
	// so blocks can write new vars to it.
	wrappedCode := fmt.Sprintf(
		"export DOCTEST_ENV_FILE=%s\nif [ -f \"$DOCTEST_ENV_FILE\" ]; then source \"$DOCTEST_ENV_FILE\"; fi\n%s",
		shellQuote(envFilePath),
		strings.TrimSpace(block.Code),
	)

	return runBashCommand(file, block, wrappedCode, timeout)
}

func findProjectRoot(startPath string) (string, error) {
	// Start from the directory containing the markdown file
	dir := filepath.Dir(startPath)
	if !filepath.IsAbs(dir) {
		var err error
		dir, err = filepath.Abs(dir)
		if err != nil {
			return "", err
		}
	}

	// Walk up the directory tree looking for project markers
	markers := []string{"go.mod", "Makefile", ".git"}

	for {
		// Check if any marker exists in current directory
		for _, marker := range markers {
			markerPath := filepath.Join(dir, marker)
			if _, err := os.Stat(markerPath); err == nil {
				return dir, nil
			}
		}

		// Move up one directory
		parent := filepath.Dir(dir)
		if parent == dir {
			// Reached filesystem root

			break
		}
		dir = parent
	}

	// Fallback: use current working directory
	cwd, err := os.Getwd()
	if err != nil {
		return "", ErrProjectRootNotFound
	}
	return cwd, nil
}

func indentOutput(output string) string {
	lines := strings.Split(output, "\n")
	for i, line := range lines {
		if line != "" {
			lines[i] = "   " + line
		}
	}
	return strings.Join(lines, "\n")
}

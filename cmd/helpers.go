package cmd

import "leakscan/internal/engine"

// buildConfig constructs an engine.Config from CLI flag values and positional args.
func buildConfig(args []string) engine.Config {
	targetPath := "."
	if len(args) > 0 {
		targetPath = args[0]
	}

	return engine.Config{
		TargetPath:       targetPath,
		IncludeGit:       includeGitHistory,
		IncludeShell:     includeShell,
		IncludeProcess:   includeProcess,
		EntropyThreshold: entropyThreshold,
		RulesFile:        rulesFileFlag,
		IgnoreFile:       ignoreFileFlag,
		MaxFileSize:      maxFileSizeFlag,
	}
}

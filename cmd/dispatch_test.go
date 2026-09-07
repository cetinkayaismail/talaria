package cmd

import (
	"sync"
	"testing"
	"time"

	"talaria/models"
)

func TestBuildModuleRegistryIntegrity(t *testing.T) {
	registry := BuildModuleRegistry()
	if len(registry) == 0 {
		t.Fatal("Expected non-empty module registry")
	}

	seen := make(map[string]bool)
	for _, mod := range registry {
		if mod.Name == "" {
			t.Errorf("Found module descriptor with empty Name")
		}
		if seen[mod.Name] {
			t.Errorf("Duplicate module name registered: %s", mod.Name)
		}
		seen[mod.Name] = true
		if mod.Phase != 1 && mod.Phase != 2 {
			t.Errorf("Module %s has invalid Phase %d (must be 1 or 2)", mod.Name, mod.Phase)
		}
		if mod.Run == nil {
			t.Errorf("Module %s has nil Run function", mod.Name)
		}
	}
}

func TestRunPhaseAliasSelectionAndExclusion(t *testing.T) {
	executed := make(map[string]bool)
	var mu sync.Mutex

	dummyRegistry := []ModuleDescriptor{
		{
			Name:    "cronjobs",
			Aliases: []string{"cron", "wildcards"},
			Phase:   1,
			Run: func(ctx *DispatchContext) error {
				mu.Lock()
				executed["cronjobs"] = true
				mu.Unlock()
				return nil
			},
		},
		{
			Name:    "sudo",
			Aliases: []string{"sudotokens", "sudokens"},
			Phase:   1,
			Run: func(ctx *DispatchContext) error {
				mu.Lock()
				executed["sudo"] = true
				mu.Unlock()
				return nil
			},
		},
		{
			Name:    "python_hijack",
			Aliases: []string{"python"},
			Phase:   1,
			Run: func(ctx *DispatchContext) error {
				mu.Lock()
				executed["python_hijack"] = true
				mu.Unlock()
				return nil
			},
		},
	}

	// 1. Select by alias "cron"
	ctx := &DispatchContext{
		Report:          &models.ScanReport{},
		Mu:              &sync.Mutex{},
		Timeout:         5 * time.Second,
		SelectedModules: map[string]bool{"cron": true},
		ExcludedModules: map[string]bool{},
		RunAll:          false,
	}
	runPhase(ctx, dummyRegistry, 1)

	if !executed["cronjobs"] {
		t.Errorf("Expected 'cronjobs' to be executed when selected by alias 'cron'")
	}
	if executed["sudo"] || executed["python_hijack"] {
		t.Errorf("Expected only 'cronjobs' to be executed")
	}

	// 2. Select All but exclude by alias "sudotokens"
	executed = make(map[string]bool)
	ctxAll := &DispatchContext{
		Report:          &models.ScanReport{},
		Mu:              &sync.Mutex{},
		Timeout:         5 * time.Second,
		SelectedModules: map[string]bool{},
		ExcludedModules: map[string]bool{"sudotokens": true},
		RunAll:          true,
	}
	runPhase(ctxAll, dummyRegistry, 1)

	if !executed["cronjobs"] {
		t.Errorf("Expected 'cronjobs' to run under RunAll")
	}
	if !executed["python_hijack"] {
		t.Errorf("Expected 'python_hijack' to run under RunAll")
	}
	if executed["sudo"] {
		t.Errorf("Expected 'sudo' to be excluded when alias 'sudotokens' is in ExcludedModules")
	}
}

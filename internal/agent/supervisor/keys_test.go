package supervisor

import (
	"os"
	"path/filepath"
	"testing"
)

// Обновление агента, меняющее сборку конфига, обязано доехать до ноды: башка
// шлёт пуш только на другую версию, а сравнивать ей не с чем
func TestAppliedVersionForgottenOnNewSchema(t *testing.T) {
	path := filepath.Join(t.TempDir(), "applied.toml")
	if err := saveAppliedVersion(path, 42); err != nil {
		t.Fatal(err)
	}
	if got := loadAppliedVersion(path); got != 42 {
		t.Fatalf("version = %d, want 42", got)
	}

	// Тот же файл, но записанный агентом с прежним генератором
	if err := os.WriteFile(path, []byte("config-version = 42\nschema = 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := loadAppliedVersion(path); got != 0 {
		t.Fatalf("устаревшая схема даёт version = %d, want 0", got)
	}
}

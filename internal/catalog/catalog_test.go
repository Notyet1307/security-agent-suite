package catalog

import "testing"

func TestLoadCatalog(t *testing.T) {
	catalog, err := Load("../../configs/agents.json")
	if err != nil {
		t.Fatal(err)
	}
	if got := len(catalog.List()); got != 5 {
		t.Fatalf("expected 5 agents, got %d", got)
	}
	attack, ok := catalog.Get("attack-path-validation")
	if !ok || !attack.RequiresApproval("active_validate") {
		t.Fatalf("attack agent approval policy missing")
	}
}

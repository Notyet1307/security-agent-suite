package catalog

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/Notyet1307/security-agent-suite/internal/domain"
)

type fileFormat struct {
	Agents []domain.AgentDefinition `json:"agents"`
}

type Catalog struct {
	byID map[string]domain.AgentDefinition
}

func Load(path string) (*Catalog, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read agent catalog: %w", err)
	}
	var file fileFormat
	if err := json.Unmarshal(data, &file); err != nil {
		return nil, fmt.Errorf("decode agent catalog: %w", err)
	}
	if len(file.Agents) == 0 {
		return nil, fmt.Errorf("agent catalog is empty")
	}
	catalog := &Catalog{byID: make(map[string]domain.AgentDefinition, len(file.Agents))}
	for _, agent := range file.Agents {
		if err := validateAgent(agent); err != nil {
			return nil, err
		}
		if _, exists := catalog.byID[agent.ID]; exists {
			return nil, fmt.Errorf("duplicate agent id %q", agent.ID)
		}
		timeout, err := time.ParseDuration(agent.DefaultTimeoutText)
		if err != nil || timeout <= 0 {
			return nil, fmt.Errorf("agent %q has invalid default_timeout %q", agent.ID, agent.DefaultTimeoutText)
		}
		agent.DefaultTimeout = timeout
		catalog.byID[agent.ID] = agent
	}
	return catalog, nil
}

func validateAgent(agent domain.AgentDefinition) error {
	if strings.TrimSpace(agent.ID) == "" || strings.TrimSpace(agent.DisplayName) == "" {
		return fmt.Errorf("agent id and display_name are required")
	}
	if strings.TrimSpace(agent.ExecutorAgent) == "" {
		return fmt.Errorf("agent %q executor_agent is required", agent.ID)
	}
	if len(agent.AllowedModes) == 0 {
		return fmt.Errorf("agent %q must allow at least one mode", agent.ID)
	}
	switch agent.Risk {
	case domain.AgentRiskLow, domain.AgentRiskMedium, domain.AgentRiskHigh:
	default:
		return fmt.Errorf("agent %q has invalid risk %q", agent.ID, agent.Risk)
	}
	return nil
}

func (c *Catalog) Get(id string) (domain.AgentDefinition, bool) {
	agent, ok := c.byID[id]
	return agent, ok
}

func (c *Catalog) List() []domain.AgentDefinition {
	result := make([]domain.AgentDefinition, 0, len(c.byID))
	for _, agent := range c.byID {
		result = append(result, agent)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].ID < result[j].ID })
	return result
}

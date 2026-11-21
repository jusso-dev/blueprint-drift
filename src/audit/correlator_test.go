package audit_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jusso-dev/blueprint-drift/src/audit"
	"github.com/jusso-dev/blueprint-drift/src/engine"
	"github.com/jusso-dev/blueprint-drift/src/graph"
	"github.com/jusso-dev/blueprint-drift/src/snapshot"
)

type failingClient struct {
	err error
}

func (f failingClient) Get(_ context.Context, _, _ string) (*graph.Response, error) {
	return nil, f.err
}

func (f failingClient) GetAllPages(_ context.Context, _, _ string) (*graph.Response, error) {
	return nil, f.err
}

func TestCorrelateEntraAndUnifiedAuditLogs(t *testing.T) {
	fromTime := time.Date(2026, 11, 20, 0, 0, 0, 0, time.UTC)
	toTime := time.Date(2026, 11, 21, 0, 0, 0, 0, time.UTC)

	report := &snapshot.DiffReport{
		FromRunID: "run-1",
		ToRunID:   "run-2",
		TenantID:  "00000000-0000-0000-0000-000000000000",
		FromTime:  fromTime,
		ToTime:    toTime,
		Changed:   2,
		Regressed: 2,
		Items: []snapshot.DiffItem{
			{
				SettingID:    "ENTRA-CA-002",
				Kind:         snapshot.ChangeChanged,
				Direction:    snapshot.DirectionRegressed,
				BeforeStatus: engine.StatusPass,
				AfterStatus:  engine.StatusFail,
				Summary:      "status pass -> fail",
			},
			{
				SettingID:    "SPO-SHARE-001",
				Kind:         snapshot.ChangeChanged,
				Direction:    snapshot.DirectionRegressed,
				BeforeStatus: engine.StatusPass,
				AfterStatus:  engine.StatusFail,
				Summary:      "status pass -> fail",
			},
		},
	}

	fx := graph.NewFixtureClient(map[string][]byte{
		"/v1.0/auditLogs/directoryAudits": []byte(`{
			"value": [
				{
					"activityDateTime": "2026-11-20T14:32:10Z",
					"activityDisplayName": "Update conditional access policy",
					"category": "Policy",
					"initiatedBy": {
						"user": {
							"userPrincipalName": "admin@agency.example.gov.au",
							"displayName": "Example Admin"
						}
					},
					"targetResources": [
						{"displayName": "BP - Block access via legacy authentication", "type": "Policy"}
					]
				}
			]
		}`),
	})

	unified, err := audit.ParseUnifiedAuditJSON([]byte(`[
		{
			"CreationTime": "2026-11-20T18:15:00Z",
			"Operation": "SharingPolicyChanged",
			"Workload": "SharePoint",
			"UserId": "spo-admin@agency.example.gov.au",
			"ObjectId": "TenantSharingSettings"
		}
	]`))
	if err != nil {
		t.Fatalf("ParseUnifiedAuditJSON: %v", err)
	}

	correlator := &audit.Correlator{
		Client:        fx,
		UnifiedEvents: unified,
	}
	correlator.Correlate(context.Background(), report)

	if report.Items[0].ChangedBy != "admin@agency.example.gov.au" || report.Items[0].ChangedAt != "2026-11-20T14:32:10Z" {
		t.Fatalf("unexpected Entra audit attribution: %+v", report.Items[0])
	}
	if report.Items[1].ChangedBy != "spo-admin@agency.example.gov.au" || report.Items[1].ChangedAt != "2026-11-20T18:15:00Z" {
		t.Fatalf("unexpected Unified audit attribution: %+v", report.Items[1])
	}

	md := snapshot.RenderMarkdown(report)
	if !strings.Contains(md, "admin@agency.example.gov.au") || !strings.Contains(md, "spo-admin@agency.example.gov.au") {
		t.Fatalf("expected actor attribution in markdown report:\n%s", md)
	}
}

func TestCorrelateHandlesMissingAuditDataGracefully(t *testing.T) {
	fromTime := time.Date(2026, 11, 20, 0, 0, 0, 0, time.UTC)
	toTime := time.Date(2026, 11, 21, 0, 0, 0, 0, time.UTC)

	report := &snapshot.DiffReport{
		FromRunID: "run-1",
		ToRunID:   "run-2",
		FromTime:  fromTime,
		ToTime:    toTime,
		Changed:   1,
		Items: []snapshot.DiffItem{
			{SettingID: "ENTRA-PROP-001", Kind: snapshot.ChangeChanged, Direction: snapshot.DirectionRegressed},
		},
	}

	correlator := &audit.Correlator{
		Client: failingClient{err: errors.New("HTTP 403 Authorization_RequestDenied")},
	}
	correlator.Correlate(context.Background(), report)

	if report.Items[0].ChangedBy != "" {
		t.Fatalf("expected empty ChangedBy when audit logs fail, got %q", report.Items[0].ChangedBy)
	}
	if !strings.Contains(report.Items[0].AuditNote, "unavailable") {
		t.Fatalf("expected graceful unavailable note, got %q", report.Items[0].AuditNote)
	}
}

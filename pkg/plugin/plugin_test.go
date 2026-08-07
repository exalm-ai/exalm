package plugin

import "testing"

func TestSplitFixesByType(t *testing.T) {
	fixes := []RemediationAction{
		{Description: "restart", FixType: "temporary"},
		{Description: "raise limit", FixType: "root-cause"},
		{Description: "unclassified"}, // empty FixType defaults to temporary
	}
	temp, root := SplitFixesByType(fixes)
	if len(temp) != 2 || temp[0].Description != "restart" || temp[1].Description != "unclassified" {
		t.Errorf("temporary: %+v", temp)
	}
	if len(root) != 1 || root[0].Description != "raise limit" {
		t.Errorf("root-cause: %+v", root)
	}

	temp, root = SplitFixesByType(nil)
	if temp != nil || root != nil {
		t.Errorf("nil input should yield nil slices, got temp=%+v root=%+v", temp, root)
	}
}

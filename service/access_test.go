package service

import (
	"reflect"
	"testing"

	"github.com/ShifdLabs/shifd-identity-service/model"
	"github.com/google/uuid"
)

func TestComputeAccess(t *testing.T) {
	cases := []struct {
		name     string
		admin    bool
		products []string
		want     []string
	}{
		{"no org, not admin", false, nil, []string{}},
		{"approval subscriber", false, []string{"shifd-approval"}, []string{"shifd-approval"}},
		{"admin without org", true, nil, []string{AccessCompanyProfileCMS}},
		{"admin with approval", true, []string{"shifd-approval"}, []string{"shifd-approval", AccessCompanyProfileCMS}},
	}
	for _, tc := range cases {
		user := &model.User{IsPlatformAdmin: tc.admin}
		if got := computeAccess(user, tc.products); !reflect.DeepEqual(got, tc.want) {
			t.Errorf("%s: computeAccess = %v, want %v", tc.name, got, tc.want)
		}
	}
}

// The access claim must be present even without an org context, otherwise a
// platform admin with no org could never enter the CMS.
func TestBuildClaimsAlwaysIncludesAccess(t *testing.T) {
	user := &model.User{ID: uuid.New(), IsPlatformAdmin: true}
	access := computeAccess(user, nil)

	claims := buildClaims(user, nil, nil, nil, access)

	if _, ok := claims["org_id"]; ok {
		t.Errorf("org_id must be omitted without membership")
	}
	if got, ok := claims["access"].([]string); !ok || !reflect.DeepEqual(got, []string{AccessCompanyProfileCMS}) {
		t.Errorf("access claim = %v, want [%s]", claims["access"], AccessCompanyProfileCMS)
	}
}

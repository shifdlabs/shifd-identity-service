package service

import (
	"testing"

	"github.com/ShifdLabs/shifd-identity-service/model"
)

// TestIsValidPlan and TestIsValidProduct cover S-13: admins must not be able to
// create subscriptions with unknown product_id / plan values that would silently
// fail to match downstream seat-limit enforcement.
func TestIsValidPlan(t *testing.T) {
	valid := []string{
		model.SubscriptionPlanTrial,
		model.SubscriptionPlanPremiumMonthly,
		model.SubscriptionPlanPremiumYearly,
	}
	for _, p := range valid {
		if !isValidPlan(p) {
			t.Errorf("isValidPlan(%q) = false, want true", p)
		}
	}

	// Old plan values (standard/professional/enterprise/large_enterprise) must
	// stay rejected now that the plan set has been replaced — regression guard
	// against accidentally re-adding them.
	invalid := []string{"", "free", "STANDARD", "premium", "unknown", "standard", "professional", "enterprise", "large_enterprise"}
	for _, p := range invalid {
		if isValidPlan(p) {
			t.Errorf("isValidPlan(%q) = true, want false", p)
		}
	}
}

func TestIsValidProduct(t *testing.T) {
	if !isValidProduct(model.ProductShifdApproval) {
		t.Errorf("isValidProduct(%q) = false, want true", model.ProductShifdApproval)
	}
	for _, p := range []string{"", "shifd-unknown", "SHIFD-APPROVAL", "approval"} {
		if isValidProduct(p) {
			t.Errorf("isValidProduct(%q) = true, want false", p)
		}
	}
}

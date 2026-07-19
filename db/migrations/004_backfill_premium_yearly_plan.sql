-- Collapses the old tiered plan values into the new plan enum
-- (trial | premium_monthly | premium_yearly). Existing subscriptions on the
-- retired standard/professional/enterprise/large_enterprise tiers become
-- premium_yearly. "trial" rows are untouched.
UPDATE subscriptions
SET plan = 'premium_yearly', updated_at = NOW()
WHERE plan IN ('standard', 'professional', 'enterprise', 'large_enterprise');

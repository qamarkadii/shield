# Error review and model improvement protocol

The model's guess is not a label. A fresh feed is source evidence; a ranking is a proxy for legitimacy. Keep those separate from analyst-confirmed outcomes.

## Review each false alarm or miss

Record the URL, normalized hostname, tenant/registered owner, source snapshot, original model hash, original verdict, suspected brand, reviewer, time, evidence reference, and one of `confirmed phishing`, `confirmed legitimate`, `uncertain`, `unavailable`. Do not collapse uncertain/unavailable into legitimate. Do not open suspicious pages in a normal browser. Use an appropriately isolated evidence service.

For legitimate free-hosted sites, verify the tenant's ownership or official project links; sharing Vercel/Netlify/GitHub hosting does not establish legitimacy. For branded paths, distinguish a credential/payment imitation from news, documentation, research, integrations and authorized partners. For official domains, ownership does not prove every URL or page is uncompromised.

The existing dashboard's binary labels lack full reviewer/evidence history. Until that schema is extended, maintain a separate versioned review ledger with evidence references and use the binary button only for supported decisions. The current database does not prove who reviewed a label. Do not claim a mature analyst feedback loop just because the button exists.

## Use reviewed examples safely

1. Assign an owner to each example, treating independent platform tenants separately.
2. Deduplicate and adjudicate contradictory labels. Public source lists can contain errors.
3. Freeze an owner-disjoint future test portion before training or inspecting examples. Development examples can be used to design features, train on hard negatives and choose thresholds. They then cease to be independent tests.
4. Add supported legitimate free-host and UAE-business hard negatives to training; preserve suspicious hosting examples too. Do not blanket-whitelist a platform or suppress all brand-path rules.
5. Train a candidate using unchanged evaluation definitions and fixed seed. The repaired retrainer accepts real analyst labels, gives them documented weight 25, and purges evaluation owners. Verify its data summary records a nonzero analyst count before saying analyst labels were used.
6. Compare candidate versus incumbent on recall, FPR, review burden, free-host/UAE-business/path slices and confidence intervals. Report rejected candidates too. Changing a threshold is operating-point calibration, not evidence the classifier learned a new feature.
7. Run one final frozen evaluation after choosing the candidate. Preserve the frozen file and avoid using successive frozen results to select experiments. A frozen set previously used for iterative decisions needs replacement with a future temporal holdout.
8. Preserve old weights, source/config/data manifests and prediction reload checks. Promote an evaluated candidate explicitly, restart/reload the service, and confirm its model hash matches the evaluated artifact. Archive and back up the milestone.

## Outcomes to measure in a pilot

Track reviewed-alert yield and review latency, not just raw flags. Track confirmed campaign evidence, authorized action acknowledgment, resolution time and domains/pages still reachable. Record first-observed events prospectively to estimate lead time against feeds, including never-matched detections and misses. Do not infer prevented losses or takedown impact from a classifier score.

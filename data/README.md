# Shield datasets

Put this whole folder in `C:\shield\data`.

| File | Rows | What it is | Use it for |
|---|---|---|---|
| `shield_training_domains.csv` | 276,270 (50/50) | `domain`, `is_phishing` (1 = phishing, 0 = legit) | Training the domain classifier |
| `shield_test_domains.csv` | 10,000 (50/50) | Same columns; no overlap with training; phishing side comes only from Phishing.Database | Honest accuracy number for the pitch |
| `uae_phishing_domains_real.csv` | 66 | Real phishing domains impersonating UAE brands (Etisalat/e&, Aramex, Emirates Post, ADCB, Emirates NBD, Mashreq, payment portals, Dubai travel lures) | Replay demo, campaign clustering, pitch examples. Not in training. |
| `phiusiil_urls_labeled.csv` | 235,795 | Full URLs with `is_phishing` | Optional: URL-level experiments |
| `train_baseline.py` | — | Ready-to-run baseline model | Starting point for the ML person |

## Baseline result (measured Nov 1)

Character n-gram logistic regression, trained on the training file:

- Test set: accuracy 0.904, precision 0.927, recall 0.878
- Real UAE fakes: 64 of 66 caught

The two it missed are `emirates-post.org` and `etisalatebills.com`: clean-looking
names with no obvious phishing pattern. That is exactly why Shield also needs the
brand-lookalike rules and the visual-similarity check, a strong point for the pitch.

## Sources and licences

- **PhiUSIIL Phishing URL Dataset** (Prasad & Chandra, 2024), UCI ML Repository, CC BY 4.0.
  134,850 legitimate + 100,945 phishing URLs. Copy taken from a GitHub mirror and
  checked: same row counts and columns as the UCI page.
- **Phishing.Database** (Mitchell Krog), MIT licence: `phishing-domains-ACTIVE.txt`,
  downloaded Nov 1, 2026.
- **Top 10,000 domains** list (GitHub: zer0h/top-1000000-domains), used as extra
  legitimate examples.

## Warnings

- **Don't trust 99% scores.** PhiUSIIL is known to be easy: its legitimate URLs are
  almost all `https://www.` and many phishing ones are not, so models learn that shortcut.
  That's why the files here are domain-only with `www.` removed, and the test set comes
  from a different source.
- **Never open these domains in a browser.** They are real phishing sites.
- Some legitimate-labelled domains may be wrong, and some phishing domains are
  compromised legitimate sites. Treat labels as mostly right, not perfect.

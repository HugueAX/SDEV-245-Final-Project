# SDEV-245-Final-Project
This scanner executes token pattern recognition leveraging standard Python standard-library regular expressions (`re`). It streams text targets line-by-line using contextual boundaries (`\b`) to enforce strict matches while filtering target noise.

The baseline catalog incorporates signature structures inspired by the `regextokens` specifications:

1. **AWS Access Key:** Evaluates structural constraints of AWS identifiers matching `AKIA` or `ASIA` string shapes followed by 16 alphanumeric characters.
2. **Stripe API Key:** Flags prefix assignments containing live or testing standard prefixes (`sk_live_`, `pk_test_`) coupled with token components.
3. **Google API Key:** Captures Google Cloud target parameters tracking standard `AIza` string starters alongside 35 base64url characters.
4. **JSON Web Token (JWT):** Identifies compact authorization tokens structured in 3 signature segments separated by periods.
5. **Asymmetric Private Key:** Scans file content blocks looking for OpenSSH/RSA cryptographic wrappers (`-----BEGIN...PRIVATE KEY-----`).
6. **Generic Credentials:** Catches assignment strings looking for common parameter variables (like `password = "..."`) using keyword-gating.

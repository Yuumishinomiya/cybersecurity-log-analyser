# Authentication Log Analyser — Learning Exercise

This is an **original, introductory practice exercise** prepared on 5 November 2026 for a 43030 professional learning portfolio. It does **not** represent historical coursework, a completed Microsoft Sentinel investigation, or proof of a cyberattack.

## Run

```bash
python log_analyser.py authentication_sample.csv
python -m unittest -v
```

## Functionality

Reads fictional CSV authentication events and counts failed logins by source IP. An IP with three or more failures is flagged **for review only**. Uses reserved documentation IP ranges (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24).

## Limitations

No time-window grouping, no false-positive reduction, no user-agent context, no threat intelligence, no actual SIEM integration. For educational use only.

## Evidence

`run_output.txt` and `test_results.txt` are genuine executions of the included script and tests in this environment. They do not prove the student personally executed the exercise; the student should review, run and explain the code before presenting this as their own achieved competence.

# Defer to Decompose (DTD) AI Control Protocols in BashArena

Code and data for the paper *Clearing Context Is Ineffective Against Practiced AI Attackers*.

The paper introduces *defer to decompose* (DTD) control protocols: when an untrusted agent
proposes an action a trusted monitor finds suspicious, the agent is terminated, and a new agent
with a cleared context resumes work on a reframed task. It compares DTD with trusted monitoring
and *defer to resample* (DTR) in the BashArena setting.

This repository contains:

- the protocol, monitor and attack-policy code the evals ran with (`tu_bb2/`);
- the launcher and post-processing scripts that produced the eval logs (`experiments/scripts/`);
- the analysis code behind every figure and table (`experiments/analysis/`, `claude_sandbox/reusable/`);
- the figures as rendered in the paper (`paper/figures/`), including embedded documentation for reproducibility;
- a download script for the eval logs and Inspect Scout scans, which are hosted on Hugging Face.

## Setup

```
uv sync
```

Python 3.13 and [uv](https://docs.astral.sh/uv/) are required. Rerunning the analysis needs
only this and the data below; Docker and model API keys are needed only to run new evals.

## Data

The eval logs and Inspect Scout scans behind the paper's figures and tables (89 GB in total)
are hosted on Hugging Face at
[xtremekiwi/dtd-basharena-data](https://huggingface.co/datasets/xtremekiwi/dtd-basharena-data),
at the same paths this repository uses. Download only what you need:

```
uv run python experiments/scripts/release_data.py list                  # groups and sizes
uv run python experiments/scripts/release_data.py download --figure 3   # one figure
uv run python experiments/scripts/release_data.py download --table 2    # one table
uv run python experiments/scripts/release_data.py download --all        # everything
```

Each file is checked against the md5 in `experiments/data/release_data_manifest.json`, which
also records which figures and tables read it. Every download includes the logs that define
the 566-task BashArena 1.0 task set, since almost every figure filters on it.

Largest groups: Figure 9 (41 GB), Figure 6 (36 GB), Figure 8 (24 GB), Figure 2 (19 GB).
The smallest (Figures 5, 7, 12) are under 3 GB each.

**The credentials in the transcripts are fake.** BashArena plants fake API keys, cloud
credentials, SSH keys and password hashes in every sandbox for the attack-mode side tasks
to target, and the transcripts show agents reading and exfiltrating them.

## Reproducing the figures and tables

Each command writes a PDF report to `experiments/data/metrics_reports_tower/<UTC time>_<name>.pdf`.
Page 1 of every report is a cover page listing the input logs, settings and caveats; the
"Page" column gives the page the paper shows. The paper's own copies are in `paper/figures/`.
Download a figure's data first (`release_data.py download --figure N`).

| | Command (`uv run python ...` unless a `.sh`) | Page |
|---|---|---|
| Fig. 1 | Flowchart, no code | |
| Fig. 2 | `claude_sandbox/reusable/ba10_analysis/plot_claims3_4_1_safety_bars.py --single-column` | 3 |
| Fig. 3 | `claude_sandbox/reusable/ba10_analysis/claim101_pareto_noplan_point.py --arm-set rf3 --task-ids BA10_UNION` | 2 |
| Fig. 4 | `experiments/analysis/plot_plan_delivery_safety_bars.py --protocol DTD` | 2 |
| Fig. 5 | `experiments/analysis/plot_decomposition_counts_and_usefulness.py` | 2 |
| Fig. 6 | `bash experiments/analysis/limit_sensitivity/_compute_rf3_actionlimit_cells.sh`, `bash experiments/analysis/limit_sensitivity/_compute_dtd_noplan_actionlimit_cells.sh`, then `experiments/analysis/limit_sensitivity/plot_safety_vs_time_and_action_limit.py` | 2 |
| Fig. 7 | `claude_sandbox/reusable/plot_redteam_win_steps_hist.py --ties all` | 8 |
| Fig. 8 | `experiments/analysis/rf3_provenance/train_test_outcomes.py`, then `experiments/analysis/rf3_provenance/plot_train_test_safety_bars.py` | 5 |
| Fig. 9 | `experiments/analysis/rf3_provenance/remediation_outcomes.py`, then `experiments/analysis/rf3_provenance/plot_remediation_safety_bars.py --with-untruncated` | 4 |
| Fig. 10 | `experiments/analysis/replay_deviation/deviation_outcomes.py > experiments/data/replay_deviation/dev_outcomes.txt`, then `experiments/analysis/replay_deviation/plot_deviation_outcomes.py` | 2 |
| Fig. 11 | `claude_sandbox/reusable/ba10_analysis/claim11_ces_vs_noplan_front.py --arm-set rf3 --task-ids BA10_UNION` | 2 |
| Fig. 12 | `experiments/analysis/compare_protocols.py`, with the arguments in the last block of `claude_sandbox/reusable/ba10_analysis/run_claims_rf3.sh` plus `--bar-figsize 4.5 3 --bar-legend-below --bar-fill 0.84` | 5 |
| Fig. 13 | `claude_sandbox/reusable/claim7_attack_selection_safety.py --protocol-set ba10_noplan_rf3 --dtrf-resample-agg q90 --xscale log --task-ids BA10_UNION` | 2 |
| Fig. 14 | `claude_sandbox/reusable/plot_category_by_child_2x2.py` | 2 |
| Fig. 15 | `experiments/analysis/plot_plan_delivery_safety_bars.py --protocol TM` | 2 |
| Table 1 | `bash claude_sandbox/reusable/ba10_analysis/claims_1_2_3_phaseA_rf3.sh` (usefulness, safety) and `experiments/analysis/compare_protocols.py --cohort phase-a-dtd-rf3 --task-ids BA10_UNION --bootstrap-ci --pdf` (AAR, AUROC) | |
| Table 2 | `experiments/analysis/eval_limit_stats/rf3_566.py` | |
| Table 3 | `experiments/analysis/side_task_test_removal/side_task_test_removal_table.py` | |

Notes:

- Figures 2, 4 and 15 draw values transcribed from earlier reports, which are kept in
  `experiments/data/metrics_reports_tower/` and named on each figure's cover page.
  `claude_sandbox/reusable/ba10_analysis/run_claims_rf3.sh` reruns the DTD ones
  (`compare_protocols.py --cohort phase-a-dtd-rf3` and `--cohort plan-ladder-rf3`), along with
  Figures 3, 11, 12 and 13 and Table 1.
- Safety and usefulness are cached per cell in `experiments/data/metrics_cache/`, so the first
  run of a figure computes from the logs and is slow (bootstrap CIs use 500 draws). Figure 6's
  plot reads only that cache, which its two shell scripts fill; for any cell still missing it
  prints the `compute_metrics.py` command that fills it.
- The defunct-malware appendix uses the Inspect Scout side-task attribution scans
  (`release_data.py download --group appendix-malware`), summarised for DTD by
  `experiments/analysis/side_task_per_child/summarize_per_child_attempts.py <scan dir>`.
- `experiments/data/claims_and_evidence_ba10.md` is the informal research log that links each
  claim to the logs and reports behind it.

## How the evals were run

Every eval was launched with `experiments/scripts/run_native.py`. Each run is an `EvalConfig`
assigned to a `RUN_*` name in that file, giving the protocol cell (monitor prompt and
thresholds), honest or attack mode, the attack policy, the task list, the limits and the
sandbox. `CONFIGS` at the bottom of the file lists the runs to launch, and `DRY_RUN = True`
(the default here) only validates and prints them. Some configs it currently defines:

- `RUN_C14_DTD_WITHTIPS_PLANCHILD0_ATTACK_THR2P333` (the one in `CONFIGS`): DTD at monitor
  threshold 2.333, attack mode, attack plan shown to the first implementer only. Produced
  `experiments/_logs/tower/2026-09-03T20-11-14_566_attack_online-dtd-v11.1-thr2p333-withtips-planchild0_BA10-UNION566.eval`
  (Figure 4).
- `RUN_C14_DTD_WITHTIPS_NOPLAN_ATTACK_THR2P333`: the paper's main DTD attack arm (no attack
  plan). Produced
  `experiments/_logs/tower/2026-08-20T22-18-47_566_attack_online-dtd-v11.1-thr2p333-withtips-noplan_BA10-UNION566.eval`.
- `RUN_C10_TM_ATTACK`: trusted monitoring, attack mode. Produced
  `experiments/_logs/tower/2026-07-15T03-59-44_629_attack_tm-v11.1_sus_BA10-UNION.eval`.

Each log's header records its full eval configuration and task list.
`tu_bb2/named_tasks_and_logs.py` (`BashArenaLogs`) groups the logs into the protocol cells the
analysis reads.

**What the evals ran on:**

- **Models:** Claude Sonnet 4.6 as the untrusted model and GPT-5.4 nano as the trusted model.
- **Protocols and monitors:** `tu_bb2/ct_ext/` (DTD is `decomposer.py`); prompts are in
  `tu_bb2/prompts/`.
- **Harness:** [control-tower](https://github.com/aaron-sandoval/control-tower), pinned in
  `uv.lock`.
- **Environment:** BashArena, the `basharena` entry in `.settings.lock.yml`
  (`linuxarena/basharena_public` at commit `46f52678`). `uv run ct settings pull` clones it
  into `.settings/`. The configs in `run_native.py` that target BashArena 1.2
  (`env="basharena2"`) were not used for the paper, and that environment is not included.
- **Docker images:** sandbox images were built from that BashArena commit and used at tag
  `latest`, as each log's `env_versions` metadata records. Task images build `FROM
  benchmark-base:latest`, whose Dockerfile is `src/base_environment/base.Dockerfile` in the
  BashArena repo.
- **Limits:** 60 agent steps and 11,700 s per sample. The paper's appendix on eval limits
  covers the message limit and how often each limit was hit.

**Post-processing:** several logs were transformed after the run.

- `experiments/scripts/rescore_native.py` adds post-hoc monitor scores to existing logs.
- `experiments/scripts/autosubmit_native.py` replayed attack trajectories to apply the
  side-task test after every action (the `_autosubmit` logs). Samples whose replay deviated
  were rerun in-loop (the `-RF3` logs, launched by the `RUN_RF3_*` configs) and merged with
  `pool_runs="dedup_latest_strict"`.
- `experiments/analysis/limit_sensitivity/claim6_giveup_counterfactuals.py` built the
  shorter-limit and give-up logs (`_actionsN`, `_actionsTotalN`, `_child0only`).

**Where the evals ran:** the original evals ran on AWS EC2 through control-tower's fleet mode
(`sandbox=EC2_SANDBOX` and its variants in `run_native.py`). `.env.example` lists the AWS
variables this needs, along with the model API keys. control-tower can also run sandboxes
in local Docker. To run a config locally:

1. Pull the environment (`uv run ct settings pull`) and have Docker available.
2. Give the config `sandbox=SandboxConfig()` (local Docker is control-tower's default), and
   cap parallelism through its limits, for example
   `limits=replace(LIMITS_STEPS_ONLY, max_samples=8, max_sandboxes=8)`.
3. Put it in `CONFIGS`, set `DRY_RUN = False`, and run
   `uv run python experiments/scripts/run_native.py`.

## Names in the code

| Paper | Code and file names |
|---|---|
| DTD | `online-dtd`, the decomposer protocol |
| DTR | `dtrf` (defer to resample with trusted fallback). BashArena 1.0 log names say `dtr-v11.1-defer*-nocache` |
| Trusted monitoring | `tm` |
| Text-file trigger protocol | `ces` (create-edit-scripts trigger) |
| Monitor sees all actions / current child task only | `tu-root-history` / `tu-full-history` |
| DTD monitor threshold, DTR defer threshold | `thr*`, `defer*` in log names |
| 566-task evaluation set | `BA10_UNION` |
| Side-task-test fix: replay / rerun | `_autosubmit` logs / `RF3` logs |

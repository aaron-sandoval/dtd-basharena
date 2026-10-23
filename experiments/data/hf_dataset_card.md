---
pretty_name: "Clearing Context Is Ineffective Against Practiced AI Attackers: eval logs"
license: cc-by-sa-4.0
viewer: false
tags:
  - ai-control
  - ai-safety
  - agents
  - inspect-ai
---

# Clearing Context Is Ineffective Against Practiced AI Attackers: eval logs

Agent trajectories and analysis outputs behind the figures and tables of the paper
*Clearing Context Is Ineffective Against Practiced AI Attackers* (Aaron Sandoval and James Lucassen). The code that produced and
analyses them is at https://github.com/aaron-sandoval/dtd-basharena.

The data are [Inspect AI](https://inspect.aisi.org.uk/) eval logs (`.eval`, zip archives) from
AI control evaluations in the BashArena setting, run with Claude Sonnet 4.6 as the untrusted
model and GPT-5.4 nano as the trusted model, plus Inspect Scout scan results (parquet)
used for the attacker-behaviour analyses. Protocols covered: trusted
monitoring, DTR (defer to resample), DTD (defer to decompose) and its
text-file trigger variant, each in honest and attack mode.

## Layout

Files sit at the same paths as in the code repository, so downloading into a clone of that
repository puts each file where the analysis scripts read it:

```
experiments/_logs/tower/<eval>.eval            eval logs used by the paper
experiments/_logs/milestone/<eval>.eval        logs defining the 566-task BashArena 1.0 split
experiments/data/scout_scans/<scan>/...        Inspect Scout scan results
release_data_manifest.json                     md5, size and figure/table use of every file
```

## Download

From a clone of the code repository:

```
uv sync
uv run python experiments/scripts/release_data.py list
uv run python experiments/scripts/release_data.py download --figure 3      # one figure
uv run python experiments/scripts/release_data.py download --all           # everything, ~89 GB
```

The script checks every file against the md5 in `release_data_manifest.json`. Without the
script, `hf download xtremekiwi/dtd-basharena-data --repo-type dataset --revision paper-v1
--local-dir <clone> --include "<path glob>"` fetches files directly.

| Group | Content | Files | Size |
|---|---|---|---|
| `base` | the 566-task BashArena 1.0 split (always downloaded) | 3 | 0.3 GB |
| `fig2` | safety bars, monitor scope and attack-plan sharing | 35 | 19.2 GB |
| `fig3` | safety vs usefulness, DTD vs DTR vs trusted monitoring | 29 | 15.8 GB |
| `fig4` | DTD safety by attack plan | 6 | 5.2 GB |
| `fig5` | decompositions and usefulness with a random trigger | 6 | 0.8 GB |
| `fig6` | safety under shorter step / working-time limits | 64 | 35.6 GB |
| `fig7` | status of DTD samples over 60 steps | 2 | 1.5 GB |
| `fig8` | safety on overlapping vs non-overlapping test subsets | 41 | 24.0 GB |
| `fig9` | safety by side-task-test remediation policy | 58 | 40.6 GB |
| `fig10` | attack samples by replay deviation score | 27 | 17.9 GB |
| `fig11` | text-file trigger protocol vs DTD vs trusted monitoring | 29 | 16.0 GB |
| `fig12` | give up after first decomposition vs always attack | 3 | 2.7 GB |
| `fig13` | safety vs up-front attack selection rate | 9 | 4.0 GB |
| `fig14` | DTD attacker behaviour by child task | 10 | 11.5 GB |
| `fig15` | trusted monitoring safety by attack plan | 17 | 7.1 GB |
| `tab1` | four DTD variants | 15 | 6.6 GB |
| `tab2` | samples affected by eval limits | 19 | 10.4 GB |
| `tab3` | samples affected by the side-task-test fix | 13 | 13.4 GB |
| `appendix-malware` | defunct malware side task (Scout side-task attribution) | 23 | 5.1 GB |

Groups overlap, since many figures share logs; the whole dataset is 153 files, 89.4 GB.

## Credentials in the transcripts are fake

BashArena plants fake secrets in every sandbox (API keys, cloud credentials, SSH keys,
password hashes) for the attack-mode side tasks to target. The transcripts show agents
reading and exfiltrating them. None of them are real credentials.

## License

CC BY-SA 4.0, matching the license of the BashArena task dataset
([Eccentricity/bashbench2](https://huggingface.co/datasets/Eccentricity/bashbench2)), whose task text
the transcripts contain.

## Citation

Citation details will be added here once the paper is on arXiv.

# T3: scan-failclosed-stealth

Scope: load_profile + discovery_seeds fail closed on IO/parse errors except missing-file fallback (mirror obfuscation loader). Stealth stagger moved inside spawned probe tasks so large scans fit overall deadline.

Accept:
- Corrupt/unreadable scan.toml errors (names field); missing file still uses shipped default.
- Stealth 100-candidate scan completes well under overall deadline; existing cap/truncate semantics kept.
- Preflight still opens zero sockets.

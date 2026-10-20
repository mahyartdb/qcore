# T4: cli-shortcut-detach

Scope: Thread validated globals (timeout, quiet, verbose, scan intent, family/prefer where applicable) through shortcut dispatch. Detach log fallback returns hop-failure instead of panicking; forward or reject report-out on detach.

Accept:
- Shortcut honors --timeout/--quiet/--verbose/--max-depth same as connect.
- Unwritable temp log path returns exit 3, never panics.
- Detach re-spawn preserves globals.

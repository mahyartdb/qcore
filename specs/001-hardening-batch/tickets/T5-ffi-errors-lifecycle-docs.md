# T5: ffi-errors-lifecycle-docs

Scope: fail_report maps from typed FailureLayer (string match fallback only). ok_string interior-NUL populates err_out. engine_free/stop bounded by engine timeout. Live-handle mutex poison-tolerant. Correct transport-set + worker_threads + full code list (1/10/12) in header/docs.

Accept:
- Forged/double-free/use-after-free still usage-error; NUL path sets err_out.
- Free/stop bounded; poisoned handle set restores instead of silently dropping.
- Header and engine_new docs match actual linked set (tor included) and knob behavior.

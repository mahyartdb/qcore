//! Shared xtask argument parsing.
//!
//! The per-subcommand `skip_while(|a| *a != "--target").nth(1)` idiom had a
//! silent failure mode: `--target=<triple>` (equals form) never matched the
//! bare flag, `.nth(1)` returned `None`, and the subcommand quietly built the
//! NATIVE target while printing the requested one nowhere. One helper now
//! parses both spellings for every subcommand, and a malformed flag fails
//! loudly instead of silently meaning "native".

/// Parse `--target <value>` / `--target=<value>`.
///
/// `Ok(None)` = flag absent (the caller applies its own default, usually
/// `native`); `Ok(Some(v))` = explicit target from either spelling;
/// `Err` = flag present but without a usable value, so a typo can never
/// silently downgrade to the native build.
pub fn parse_target_arg(args: &[String]) -> Result<Option<String>, String> {
    flag_value(args, "--target")
}

/// Parse `--<name> <value>` / `--<name>=<value>` for any long flag.
///
/// `Ok(None)` = flag absent; `Ok(Some(v))` = value from either spelling;
/// `Err` = flag present but valueless (dangling `--<name>` or empty
/// `--<name>=`). Only the first occurrence is returned; xtask subcommands
/// take each flag at most once.
pub fn flag_value(args: &[String], name: &str) -> Result<Option<String>, String> {
    let equals_form = format!("{name}=");
    let mut it = args.iter();
    while let Some(a) = it.next() {
        if let Some(v) = a.strip_prefix(&equals_form) {
            if v.is_empty() {
                return Err(format!("{name}= given without a value"));
            }
            return Ok(Some(v.to_string()));
        }
        if a == name {
            return match it.next() {
                Some(v) if !v.is_empty() => Ok(Some(v.clone())),
                _ => Err(format!("{name} given without a value")),
            };
        }
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::{flag_value, parse_target_arg};

    fn args(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn space_and_equals_forms_agree() {
        // Both spellings must resolve to the same explicit target — the old
        // `skip_while` idiom silently treated the equals form as absent.
        let space = parse_target_arg(&args(&["--target", "x86_64-unknown-linux-gnu"]));
        let equals = parse_target_arg(&args(&["--target=x86_64-unknown-linux-gnu"]));
        assert_eq!(space, Ok(Some("x86_64-unknown-linux-gnu".to_string())));
        assert_eq!(space, equals);
    }

    #[test]
    fn space_form_after_other_flags() {
        let a = args(&["--release", "--target", "aarch64-linux-android", "--json"]);
        assert_eq!(
            parse_target_arg(&a),
            Ok(Some("aarch64-linux-android".to_string()))
        );
    }

    #[test]
    fn absent_flag_is_none_not_native() {
        // Absence is the caller's decision (native default); the helper only
        // reports what it saw.
        assert_eq!(parse_target_arg(&args(&[])), Ok(None));
        assert_eq!(
            parse_target_arg(&args(&["--allow-partial-matrix"])),
            Ok(None)
        );
    }

    #[test]
    fn malformed_forms_fail_loudly() {
        // Dangling `--target` (no following value) and the empty equals form
        // used to fall through to the native default; both are now errors.
        assert!(parse_target_arg(&args(&["--target"])).is_err());
        assert!(parse_target_arg(&args(&["--target="])).is_err());
        assert!(parse_target_arg(&args(&["--target", ""])).is_err());
    }

    #[test]
    fn flag_value_generalizes_to_other_names() {
        let a = args(&["--staged-artifacts=target/dist"]);
        assert_eq!(
            flag_value(&a, "--staged-artifacts"),
            Ok(Some("target/dist".to_string()))
        );
        assert_eq!(flag_value(&a, "--target"), Ok(None));
        assert!(flag_value(&args(&["--staged-artifacts"]), "--staged-artifacts").is_err());
    }
}

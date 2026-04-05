use clap::{Arg, ArgAction, ArgMatches, Command};
use fake_tcp::MimicProfile;

/// Add `--mimic` and `--mimic-no-*` arguments to a clap Command.
pub fn add_mimic_args(cmd: Command) -> Command {
    cmd.arg(
        Arg::new("mimic")
            .long("mimic")
            .required(false)
            .value_name("PROFILE")
            .help(
                "Mimic a specific TCP fingerprint profile. Currently supported: \"udp2raw\". \
                 When active, forces stealth to at least Standard level.",
            ),
    )
    .arg(
        Arg::new("mimic_no_ipid")
            .long("mimic-no-ipid")
            .required(false)
            .action(ArgAction::SetTrue)
            .requires("mimic")
            .help("Disable incrementing IP ID (use default IP ID=0 with DF flag)"),
    )
    .arg(
        Arg::new("mimic_no_wscale")
            .long("mimic-no-wscale")
            .required(false)
            .action(ArgAction::SetTrue)
            .requires("mimic")
            .help("Disable window scale override (use default wscale=7)"),
    )
    .arg(
        Arg::new("mimic_no_psh")
            .long("mimic-no-psh")
            .required(false)
            .action(ArgAction::SetTrue)
            .requires("mimic")
            .help("Disable PSH suppression (use PSH on all data packets like stealth Basic+)"),
    )
    .arg(
        Arg::new("mimic_no_window")
            .long("mimic-no-window")
            .required(false)
            .action(ArgAction::SetTrue)
            .requires("mimic")
            .help("Disable raw window override (use phantun's default window computation)"),
    )
}

/// Build a `MimicProfile` from parsed CLI arguments.
///
/// Returns `None` if `--mimic` was not specified.
/// Panics if `--mimic` value is not a recognized profile name.
pub fn build_mimic_profile(matches: &ArgMatches) -> Option<MimicProfile> {
    let profile_name = matches.get_one::<String>("mimic")?;

    let mut profile = match profile_name.as_str() {
        "udp2raw" => MimicProfile::udp2raw(),
        other => panic!("unknown mimic profile: {other}"),
    };

    if matches.get_flag("mimic_no_ipid") {
        profile.ip_id_incrementing = false;
    }
    if matches.get_flag("mimic_no_wscale") {
        profile.wscale = 7;
    }
    if matches.get_flag("mimic_no_psh") {
        profile.psh_always = true;
    }
    if matches.get_flag("mimic_no_window") {
        // window_raw=0 signals Socket::new() to use default window computation
        profile.window_raw = 0;
    }

    Some(profile)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_command() -> Command {
        add_mimic_args(
            Command::new("test")
                .arg(Arg::new("local").short('l').long("local").required(true))
                .arg(Arg::new("remote").short('r').long("remote").required(true)),
        )
    }

    #[test]
    fn test_no_mimic_flag() {
        let matches = test_command()
            .try_get_matches_from(["test", "-l", "127.0.0.1:1234", "-r", "10.0.0.1:5678"])
            .unwrap();
        assert!(build_mimic_profile(&matches).is_none());
    }

    #[test]
    fn test_mimic_udp2raw_defaults() {
        let matches = test_command()
            .try_get_matches_from([
                "test",
                "-l",
                "127.0.0.1:1234",
                "-r",
                "10.0.0.1:5678",
                "--mimic",
                "udp2raw",
            ])
            .unwrap();
        let profile = build_mimic_profile(&matches).unwrap();
        assert!(profile.ip_id_incrementing);
        assert_eq!(profile.wscale, 5);
        assert_eq!(profile.window_raw, 41000);
        assert!(!profile.psh_always);
    }

    #[test]
    fn test_mimic_no_ipid() {
        let matches = test_command()
            .try_get_matches_from([
                "test",
                "-l",
                "127.0.0.1:1234",
                "-r",
                "10.0.0.1:5678",
                "--mimic",
                "udp2raw",
                "--mimic-no-ipid",
            ])
            .unwrap();
        let profile = build_mimic_profile(&matches).unwrap();
        assert!(!profile.ip_id_incrementing);
        // Other fields unchanged
        assert_eq!(profile.wscale, 5);
        assert_eq!(profile.window_raw, 41000);
        assert!(!profile.psh_always);
    }

    #[test]
    fn test_mimic_no_wscale() {
        let matches = test_command()
            .try_get_matches_from([
                "test",
                "-l",
                "127.0.0.1:1234",
                "-r",
                "10.0.0.1:5678",
                "--mimic",
                "udp2raw",
                "--mimic-no-wscale",
            ])
            .unwrap();
        let profile = build_mimic_profile(&matches).unwrap();
        assert!(profile.ip_id_incrementing);
        assert_eq!(profile.wscale, 7);
        assert_eq!(profile.window_raw, 41000);
        assert!(!profile.psh_always);
    }

    #[test]
    fn test_mimic_no_psh() {
        let matches = test_command()
            .try_get_matches_from([
                "test",
                "-l",
                "127.0.0.1:1234",
                "-r",
                "10.0.0.1:5678",
                "--mimic",
                "udp2raw",
                "--mimic-no-psh",
            ])
            .unwrap();
        let profile = build_mimic_profile(&matches).unwrap();
        assert!(profile.ip_id_incrementing);
        assert_eq!(profile.wscale, 5);
        assert_eq!(profile.window_raw, 41000);
        assert!(profile.psh_always);
    }

    #[test]
    fn test_mimic_no_window() {
        let matches = test_command()
            .try_get_matches_from([
                "test",
                "-l",
                "127.0.0.1:1234",
                "-r",
                "10.0.0.1:5678",
                "--mimic",
                "udp2raw",
                "--mimic-no-window",
            ])
            .unwrap();
        let profile = build_mimic_profile(&matches).unwrap();
        assert!(profile.ip_id_incrementing);
        assert_eq!(profile.wscale, 5);
        assert_eq!(profile.window_raw, 0);
        assert!(!profile.psh_always);
    }

    #[test]
    fn test_mimic_all_toggles_disabled() {
        let matches = test_command()
            .try_get_matches_from([
                "test",
                "-l",
                "127.0.0.1:1234",
                "-r",
                "10.0.0.1:5678",
                "--mimic",
                "udp2raw",
                "--mimic-no-ipid",
                "--mimic-no-wscale",
                "--mimic-no-psh",
                "--mimic-no-window",
            ])
            .unwrap();
        let profile = build_mimic_profile(&matches).unwrap();
        assert!(!profile.ip_id_incrementing);
        assert_eq!(profile.wscale, 7);
        assert_eq!(profile.window_raw, 0);
        assert!(profile.psh_always);
    }

    #[test]
    fn test_mimic_toggle_without_mimic_fails() {
        let result = test_command().try_get_matches_from([
            "test",
            "-l",
            "127.0.0.1:1234",
            "-r",
            "10.0.0.1:5678",
            "--mimic-no-ipid",
        ]);
        assert!(result.is_err());
    }

    #[test]
    #[should_panic(expected = "unknown mimic profile")]
    fn test_unknown_mimic_profile() {
        let matches = test_command()
            .try_get_matches_from([
                "test",
                "-l",
                "127.0.0.1:1234",
                "-r",
                "10.0.0.1:5678",
                "--mimic",
                "nonexistent",
            ])
            .unwrap();
        build_mimic_profile(&matches);
    }
}

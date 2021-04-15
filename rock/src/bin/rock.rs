//Run this code with cargo
// Join test.com AD domain on CentOS 7 with SSSD enabled.
// Shell command this program trying to replace with.

// Debug:
// 1. cargo build && target/debug/rock -j -a myaccount  -p password
// 2. cargo build && target/debug/rock -c
// Reference:
// 1. http://siciarz.net/24-days-rust-clap/
//
// rocky
//
// get  
// build
// mkcfg
// patch
// prep
// 
//use std::error::Error;

extern crate clap;
use clap::{App, Arg};
extern crate rexpect;
use rexpect::errors::*;
use rexpect::process::wait;
use rexpect::spawn;
use std::env;
use std::fs;
extern crate oping;
//extern crate os_info;
use oping::{Ping, PingResult};

fn build(domain: &str) -> Result<()> {
    //! TBC
    //!
    let ldomain: &str = domain;
    let cmd_prefix = "/usr/sbin/realm discover ";
    let realm_suffix = "";
    let discover_command = [cmd_prefix, realm_suffix].join(ldomain);
    // println!("discover_command:{N}", N = discover_command);
    let mut p = spawn(&discover_command, Some(30_000))?;
    match p.process.wait() {
        Ok(wait::WaitStatus::Exited(_, 0)) => {
            println!("{a1} exited with code 0, all good!", a1 = discover_command)
        }
        Ok(wait::WaitStatus::Exited(_, c)) => {
            println!(
                "Command: {a1} exited with code {c1}.",
                a1 = discover_command,
                c1 = c
            );
            println!("Output (stdout and stderr): {}", p.exp_eof()?);
        }
        _ => println!(
            "{a1} exited with code >0, or it was killed.",
            a1 = discover_command
        ),
    }
    p.exp_eof()?;
    Ok(())
}


fn get(domain: &str) -> Result<()> {
    //! TBC
    //!
    let ldomain: &str = domain;
    let cmd_prefix = "/usr/sbin/realm discover ";
    let realm_suffix = "";

    let discover_command = [cmd_prefix, realm_suffix].join(ldomain);
    // println!("discover_command:{N}", N = discover_command);
    let mut p = spawn(&discover_command, Some(30_000))?;
    match p.process.wait() {
        Ok(wait::WaitStatus::Exited(_, 0)) => {
            println!("{a1} exited with code 0, all good!", a1 = discover_command)
        }
        Ok(wait::WaitStatus::Exited(_, c)) => {
            println!(
                "Command: {a1} exited with code {c1}.",
                a1 = discover_command,
                c1 = c
            );
            println!("Output (stdout and stderr): {}", p.exp_eof()?);
        }
        _ => println!(
            "{a1} exited with code >0, or it was killed.",
            a1 = discover_command
        ),
    }
    p.exp_eof()?;
    Ok(())
}

fn mkcfg(domain: &str) -> Result<()> {
    //! TBC
    //!
    let ldomain: &str = domain;
    let cmd_prefix = "/usr/sbin/realm discover ";
    let realm_suffix = "";

    let discover_command = [cmd_prefix, realm_suffix].join(ldomain);
    // println!("discover_command:{N}", N = discover_command);
    let mut p = spawn(&discover_command, Some(30_000))?;
    match p.process.wait() {
        Ok(wait::WaitStatus::Exited(_, 0)) => {
            println!("{a1} exited with code 0, all good!", a1 = discover_command)
        }
        Ok(wait::WaitStatus::Exited(_, c)) => {
            println!(
                "Command: {a1} exited with code {c1}.",
                a1 = discover_command,
                c1 = c
            );
            println!("Output (stdout and stderr): {}", p.exp_eof()?);
        }
        _ => println!(
            "{a1} exited with code >0, or it was killed.",
            a1 = discover_command
        ),
    }
    p.exp_eof()?;
    Ok(())
}

fn patch(domain: &str) -> Result<()> {
    //! TBC
    //!
    let ldomain: &str = domain;
    let cmd_prefix = "/usr/sbin/realm discover ";
    let realm_suffix = "";

    let discover_command = [cmd_prefix, realm_suffix].join(ldomain);
    // println!("discover_command:{N}", N = discover_command);
    let mut p = spawn(&discover_command, Some(30_000))?;
    match p.process.wait() {
        Ok(wait::WaitStatus::Exited(_, 0)) => {
            println!("{a1} exited with code 0, all good!", a1 = discover_command)
        }
        Ok(wait::WaitStatus::Exited(_, c)) => {
            println!(
                "Command: {a1} exited with code {c1}.",
                a1 = discover_command,
                c1 = c
            );
            println!("Output (stdout and stderr): {}", p.exp_eof()?);
        }
        _ => println!(
            "{a1} exited with code >0, or it was killed.",
            a1 = discover_command
        ),
    }
    p.exp_eof()?;
    Ok(())
}

fn prep(domain: &str) -> Result<()> {
    //! TBC
    //!
    let ldomain: &str = domain;
    let cmd_prefix = "/usr/sbin/realm discover ";
    let realm_suffix = "";

    let discover_command = [cmd_prefix, realm_suffix].join(ldomain);
    // println!("discover_command:{N}", N = discover_command);
    let mut p = spawn(&discover_command, Some(30_000))?;
    match p.process.wait() {
        Ok(wait::WaitStatus::Exited(_, 0)) => {
            println!("{a1} exited with code 0, all good!", a1 = discover_command)
        }
        Ok(wait::WaitStatus::Exited(_, c)) => {
            println!(
                "Command: {a1} exited with code {c1}.",
                a1 = discover_command,
                c1 = c
            );
            println!("Output (stdout and stderr): {}", p.exp_eof()?);
        }
        _ => println!(
            "{a1} exited with code >0, or it was killed.",
            a1 = discover_command
        ),
    }
    p.exp_eof()?;
    Ok(())
}


fn do_pings() -> PingResult<()> {
    // $ setcap cap_net_raw+ep $MY_BINARY    # allow binary to send ping packets
    let mut ping = Ping::new();
    try!(ping.set_timeout(5.0)); // timeout of 5.0 seconds
    try!(ping.add_host("localhost")); // fails here if socket can't be created
    try!(ping.add_host("127.0.0.1"));
    //    try!(ping.add_host("::1")); // IPv4 / IPv6 addresses OK
    //    try!(ping.add_host("1.2.3.4"));
    let responses = try!(ping.send());
    for resp in responses {
        if resp.dropped > 0 {
            println!("No response from host: {}", resp.hostname);
        } else {
            println!(
                "Response from host {} (address {}): latency {} ms",
                resp.hostname, resp.address, resp.latency_ms
            );
            println!("    all details: {:?}", resp);
        }
    }
    Ok(())
}

fn discover_ad(domain: &str) -> Result<()> {
    //! TBC
    //!
    let ldomain: &str = domain;
    // println!("laccount/lpassword:{N}/{P}", N = laccount, P = lpassword);
    let cmd_prefix = "/usr/sbin/realm discover ";
    let realm_suffix = "";
    let discover_command = [cmd_prefix, realm_suffix].join(ldomain);
    // println!("discover_command:{N}", N = discover_command);
    let mut p = spawn(&discover_command, Some(30_000))?;
    match p.process.wait() {
        Ok(wait::WaitStatus::Exited(_, 0)) => {
            println!("{a1} exited with code 0, all good!", a1 = discover_command)
        }
        Ok(wait::WaitStatus::Exited(_, c)) => {
            println!(
                "Command: {a1} exited with code {c1}.",
                a1 = discover_command,
                c1 = c
            );
            println!("Output (stdout and stderr): {}", p.exp_eof()?);
        }
        _ => println!(
            "{a1} exited with code >0, or it was killed.",
            a1 = discover_command
        ),
    }
    p.exp_eof()?;
    Ok(())
}

fn is_program_in_path(program: &str) -> bool {
    if let Ok(path) = env::var("PATH") {
        for p in path.split(":") {
            let p_str = format!("{}/{}", p, program);
            if fs::metadata(p_str).is_ok() {
                return true;
            }
        }
    }
    false
}

fn join(account: &str, password: &str) -> Result<()> {
    //! Password for admin_miq:

    let lpassword: &str = password;
    // println!("laccount/lpassword:{N}/{P}", N = laccount, P = lpassword);
    let laccount: &str = account;
    let cmd_prefix   = "/usr/sbin/realm join -v --membership-software=adcli --computer-ou=ou=my-ou1,ou=servers,dc=test,dc=com test.com  -U ";
    let realm_suffix = "";
    let joincommand = [cmd_prefix, realm_suffix].join(laccount);
    println!("joincommand:{N}", N = joincommand);
    let mut p = spawn(&joincommand, Some(30_000))?;
    let s1 = "\n.*";
    let s3 = ": ";
    let regex_login = [s1, s3].join(laccount);
    //p.exp_regex("\n.*admin_miq: ")?;
    p.exp_regex(&regex_login)?;
    p.send_line(lpassword)?;
    match p.process.wait() {
        Ok(wait::WaitStatus::Exited(_, 0)) => {
            println!("{a1} exited with code 0, all good!", a1 = joincommand)
        }
        Ok(wait::WaitStatus::Exited(_, c)) => {
            println!(
                "Command: {a1} exited with code {c1}.",
                a1 = joincommand,
                c1 = c
            );
            println!("Output (stdout and stderr): {}", p.exp_eof()?);
        }
        _ => println!(
            "{a1} exited with code >0, or it was killed.",
            a1 = joincommand
        ),
    }
    p.exp_eof()?;
    Ok(())
}

fn leave(account: &str, password: &str) -> Result<()> {
    let laccount: &str = account;
    let lpassword: &str = password;
    println!("laccount/lpassword:{N}/{P}", N = laccount, P = lpassword);
    let leave_prefix = "/usr/sbin/realm leave test.com -U ";
    let leave_suffix = "";
    let leavecommand = [leave_prefix, leave_suffix].join(laccount);
    // println!("leavecommand:{N}", N = leavecommand);
    let mut p = spawn(&leavecommand, Some(30_000))?;
    let s1 = "Password for ";
    let s3 = ": ";
    let regex_password = [s1, s3].join(laccount);
    p.exp_regex(&regex_password)?;
    p.send_line(lpassword)?;
    match p.process.wait() {
        Ok(wait::WaitStatus::Exited(_, 0)) => println!("realm exited with code 0, all good!"),
        _ => println!("realm exited with code >0, or it was killed"),
    }
    p.exp_eof()?;
    Ok(())
}

//fn ostype() {
//    let info = os_info::get();
//    println!("OS information: {}", info);
//    println!("Type: {}", info.os_type());
//    println!("Version: {}", info.version());
//}
//
fn main() {
    //    join().unwrap_or_else(|e| panic!("Failed to joing test.com AD domain {}", e));
    let matches = App::new("rock")
        .version("0.1.2")
        .author("tjyang2001@gmail.com")
        .about("test.com AD tool using Rust\nEx1: cargo run --bin testad  -- -c -l ldap://ldap.forumsys.com:389 -a read-only-admin -p password.\nEx2: ldapcheck03 --check -l ldap://ldap.forumsys.com:389 -a read-only-admin -p password\nEx3: testad --join -a admin_itcode -p mypasswd\nEx4: testad --leave -a admin_itcode -p mypasswd")

        .arg(
            Arg::with_name("account")
                .short("a")
                .long("account")
                .value_name("Account name for LDAP server")
                .takes_value(true)
                .help("ldap account name"),
        ).arg(
            Arg::with_name("get")
                .short("g")
                .long("get")
                .value_name("get")
                .takes_value(true)
                .help("Getting rpm-name from rocky repo"),
        ).arg(
            Arg::with_name("build")
                .short("b")
                .long("build")
                .value_name("build")
                .takes_value(true)
                .help("Post rpm get to build rpm in local mock"),
        ).arg(
            Arg::with_name("mkcfg")
                .short("m")
                .long("mkcfg")
                .value_name("mkcfg")
                .takes_value(true)
                .help("Post rpm get to build rpm in local mock"),
        ).arg(
            Arg::with_name("patch")
                .short("t")
                .long("patch")
                .value_name("patch")
                .takes_value(true)
                .help("Post rpm get to build rpm in local mock"),
        ).arg(
            Arg::with_name("prep")
                .short("k")
                .long("prep")
                .value_name("prep")
                .takes_value(true)
                .help("Post rpm get to build rpm in local mock"),
	).arg(
            Arg::with_name("password")
                .short("p")
                .long("password")
                .value_name("Passord for LDAP Server")
                .takes_value(true)
                .help("ldap password"),
        ).arg(
            Arg::with_name("join")
                .short("j")
                .long("join")
                .help("Joining this host to test.com AD domain."),
        ).arg(
            Arg::with_name("leave")
                .short("l")
                .long("leave")
                .help("Taking this host out of test.com AD binding."),
        ).arg(
            Arg::with_name("check")
                .short("c")
                .long("check")
                .help("Check this host test.com AD configuration."),
        ).get_matches();

    let program = "realm"; // realm should exists.
    assert!(
        is_program_in_path(program),
        "Chekcing /usr/sbin/realm, it not found in $PATH."
    );

    // Main : user matches
    if matches.is_present("check") {
        println!("check:{P}", P = "check provided");

        match do_pings() {
            Ok(_) => (),
            Err(e) => {
                println!("{}", e);
                ()
            }
        }
//        ostype();
//        let domain = "test.com"; // realm should exists.
//        match discover_ad(&domain) {
//            Ok(_) => (),
//            Err(e) => {
//                println!("{}", e);
//                ()
//            }
//        }
        
    }

    if matches.is_present("join") {
        let account = matches.value_of("account").unwrap();
        let ldappassword = matches.value_of("password").unwrap();
        // println!("account:{N}", N=account);
        // println!("account:{P}", P=ldappassword);

        match join(account, ldappassword) {
            //case workflow.
            Ok(_) => println!(
                "OK to join test.com AD using account/password:{NAME}/{PW}",
                NAME = account,
                PW = ldappassword
            ),
            Err(e) => println!("{:?}", e),
        }
    }
    if matches.is_present("leave") {
        let account = matches.value_of("account").unwrap();
        let ldappassword = matches.value_of("password").unwrap();

        match leave(account, ldappassword) {
            //case workflow.
            Ok(_) => println!(
                "OK to leave test.com AD using account/password:{NAME}/{PW}",
                NAME = account,
                PW = ldappassword
            ),
            Err(e) => println!("{:?}", e),
        }
    }
}

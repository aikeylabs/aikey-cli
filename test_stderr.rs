use std::io::Write;

fn main() {
    let mut stderr = std::io::stderr();
    writeln!(stderr, "Line 1").unwrap();
    writeln!(stderr, "Line 2").unwrap();
    writeln!(stderr, "Line 3").unwrap();
    stderr.flush().unwrap();
    std::process::exit(1);
}

// File: src\bin\otp.rs
// Author: Hadi Cahyadi <cumulus13@gmail.com>
// Date: 2026-10-28
// Description: `otp` — short alias for the `otpforge` binary.
// License: MIT

#[path = "../main.rs"]
mod app;

fn main() -> std::process::ExitCode {
    app::main()
}

use anyhow::{bail, Context, Result};
use nix::pty::openpty;
use nix::sys::termios::{tcgetattr, tcsetattr, SetArg};
use nix::unistd::{close, dup2, execvp, fork, ForkResult};
use std::ffi::CString;
use std::fs::OpenOptions;
use std::io::{self, Read, Write};
use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use crate::evidence::EvidenceVault;
use crate::utils::crypto::sha256_bytes;
use crate::utils::timestamps::now_rfc3339;

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct TerminalChunk {
    pub timestamp: String,
    pub direction: String, // "stdin" or "stdout"
    pub bytes_len: usize,
    pub data_hex: String,
    pub chunk_hash: String,
}

pub struct PtyRecorder {
    log_file: PathBuf,
}

impl PtyRecorder {
    pub fn new<P: AsRef<Path>>(log_file: P) -> Self {
        Self {
            log_file: log_file.as_ref().to_path_buf(),
        }
    }

    /// Spawn a command inside a pseudo-terminal while capturing all I/O
    pub fn run_session(&self, command_args: &[String], vault: Arc<EvidenceVault>) -> Result<i32> {
        // Query caller's terminal window size so child PTY has matching columns/rows
        let mut ws: libc::winsize = unsafe { std::mem::zeroed() };
        let has_ws = unsafe { libc::ioctl(libc::STDIN_FILENO, libc::TIOCGWINSZ, &mut ws) } == 0;
        let nix_ws = if has_ws && ws.ws_col > 0 && ws.ws_row > 0 {
            Some(nix::pty::Winsize {
                ws_row: ws.ws_row,
                ws_col: ws.ws_col,
                ws_xpixel: ws.ws_xpixel,
                ws_ypixel: ws.ws_ypixel,
            })
        } else {
            None
        };

        let pty = openpty(nix_ws.as_ref(), None).context("Failed to open PTY master/slave pair")?;
        let master_fd = pty.master;
        let slave_fd = pty.slave;

        // Put stdin in raw mode so all keystrokes pass directly to PTY
        let stdin = io::stdin();
        let orig_termios = tcgetattr(&stdin).ok();

        if let Some(ref term) = orig_termios {
            let mut raw_term = term.clone();
            nix::sys::termios::cfmakeraw(&mut raw_term);
            let _ = tcsetattr(&stdin, SetArg::TCSANOW, &raw_term);
        }

        match unsafe { fork() } {
            Ok(ForkResult::Child) => {
                // Child: attach slave PTY to stdin, stdout, stderr
                close(master_fd.as_raw_fd()).ok();

                unsafe {
                    libc::setsid();
                    libc::ioctl(slave_fd.as_raw_fd(), libc::TIOCSCTTY as _, 0);
                }

                dup2(slave_fd.as_raw_fd(), 0).expect("dup2 0");
                dup2(slave_fd.as_raw_fd(), 1).expect("dup2 1");
                dup2(slave_fd.as_raw_fd(), 2).expect("dup2 2");
                close(slave_fd.as_raw_fd()).ok();

                let prog = CString::new(command_args[0].clone()).unwrap();
                let c_args: Vec<CString> = command_args
                    .iter()
                    .map(|s| CString::new(s.as_str()).unwrap())
                    .collect();

                let _ = execvp(&prog, &c_args);
                std::process::exit(127);
            }
            Ok(ForkResult::Parent { child }) => {
                // Parent: bridge user terminal and master PTY while recording
                close(slave_fd.as_raw_fd()).ok();

                let running = Arc::new(AtomicBool::new(true));
                let mut log_out = OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(&self.log_file)
                    .context("Failed to open terminal stream log")?;

                let master_raw = master_fd.as_raw_fd();

                // Thread to copy stdin -> master PTY
                let r_clone = running.clone();
                std::thread::spawn(move || {
                    let mut buf = [0u8; 1024];
                    let mut stdin_reader = io::stdin();
                    while r_clone.load(Ordering::Relaxed) {
                        if let Ok(n) = stdin_reader.read(&mut buf) {
                            if n == 0 {
                                break;
                            }
                            let _ = unsafe { libc::write(master_raw, buf.as_ptr() as _, n) };
                        }
                    }
                });

                // Main loop: read master PTY -> stdout & log file
                let mut buf = [0u8; 4096];
                let mut stdout = io::stdout();

                loop {
                    let n = unsafe { libc::read(master_raw, buf.as_mut_ptr() as _, buf.len()) };
                    if n <= 0 {
                        break;
                    }
                    let chunk_bytes = &buf[..n as usize];
                    let _ = stdout.write_all(chunk_bytes);
                    let _ = stdout.flush();

                    // Record to JSONL stream
                    let chunk_hash = sha256_bytes(chunk_bytes);
                    let rec = TerminalChunk {
                        timestamp: now_rfc3339(),
                        direction: "stdout".to_string(),
                        bytes_len: n as usize,
                        data_hex: hex::encode(chunk_bytes),
                        chunk_hash: chunk_hash.clone(),
                    };

                    if let Ok(line) = serde_json::to_string(&rec) {
                        let _ = writeln!(log_out, "{}", line);
                        let _ = log_out.flush();
                    }

                    // Periodic hash chain sample
                    let _ = vault.record_event("PTY_OUTPUT", &chunk_hash);
                }

                running.store(false, Ordering::Relaxed);

                // Restore original terminal settings
                if let Some(ref term) = orig_termios {
                    let _ = tcsetattr(&stdin, SetArg::TCSANOW, term);
                }

                // Wait for child process exit
                let mut status = 0;
                unsafe { libc::waitpid(child.as_raw(), &mut status, 0) };
                let exit_code = if libc::WIFEXITED(status) {
                    libc::WEXITSTATUS(status)
                } else {
                    1
                };

                Ok(exit_code)
            }
            Err(e) => {
                if let Some(ref term) = orig_termios {
                    let _ = tcsetattr(&stdin, SetArg::TCSANOW, term);
                }
                bail!("Fork failed: {}", e)
            }
        }
    }
}

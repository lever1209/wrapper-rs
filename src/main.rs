use std::{
	io::{stdin, Read, Write},
	net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener},
	path::Path,
	process::Stdio,
	sync::mpsc,
	thread::{self, Thread},
	time::Duration,
};

fn main() {
	let (tx, rx) = mpsc::channel();

	let mut proc = std::process::Command::new(
		Path::new("run/terraria/bin/TerrariaServer.bin.x86_64")
			.canonicalize()
			.unwrap(),
	);

	thread::spawn(move || {
		let sockaddr: SocketAddr = "127.0.0.1:49634".parse().expect("invalid ip");
		loop {
			// let listener = TcpListener::bind(sockaddr).unwrap();
			// let (mut stream, addr) = listener.accept().unwrap();
			// let mut buf: [u8; 20] = [0; 20];

			// stream.read(&mut buf).unwrap();
			
			

			{
				let listener = TcpListener::bind(sockaddr).unwrap();
				let (mut stream, addr) = listener.accept().unwrap();
				let mut buf = String::new();

				stream.read_to_string(&mut buf).unwrap();

				tx.send(buf).unwrap();
			}
		}
	});

	let mut proc = proc
		.stdin(Stdio::piped())
		.stderr(Stdio::inherit())
		.stdout(Stdio::inherit())
		.current_dir(Path::new("run/terraria/wdir").canonicalize().unwrap())
		.spawn();
	// .expect("spawn");

	match proc {
		Ok(mut child) => {
			let mut stdin_pipe = child.stdin.take().expect("could not take stdin");

			loop {
				match rx.recv_timeout(Duration::new(1, 0)) {
					Ok(to_write) => {
						stdin_pipe
							.write_all(to_write.as_bytes())
							.expect("could not write to stdin of child");
						stdin_pipe.flush().unwrap();
					}
					Err(_) => match child.try_wait() {
						Ok(Some(_)) => break,
						Ok(None) => (),
						Err(e) => eprintln!("{e}"),
					},
				}
			}
		}
		Err(_) => println!("proc failed to start"),
	}

	// proc.wait().unwrap();
}

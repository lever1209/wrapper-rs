use std::{
	ascii::AsciiExt,
	char,
	io::{stdin, Read, Write},
	net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener},
	ops::Add,
	path::Path,
	process::Stdio,
	sync::mpsc,
	thread::{self, Thread},
	time::Duration,
};

#[derive(Debug)]
struct RconPacket {
	size: i32,
	id: i32,
	ptype: i32,
	body: String,
	term: u8,
}

fn main() {
	let sockaddr: SocketAddr = "127.0.0.1:49634".parse().expect("invalid ip");

	let listener = TcpListener::bind(sockaddr).unwrap();
	let (mut stream, addr) = listener.accept().unwrap();

	loop {
		println!("listening for packet");
		let mut buf = [0; 32];

		stream.read(&mut buf).unwrap();

		let buf = buf.to_vec();

		dbg!(&buf);

		let packet = RconPacket {
			size: (&buf[0] << &buf[1] << &buf[2] << &buf[3]).into(),
			id: (&buf[4] << &buf[5] << &buf[6] << &buf[7]).into(),
			ptype: (&buf[8] << &buf[9] << &buf[10] << &buf[11]).into(),
			body: {
				let mut return_val = String::new();
				for i in 12..(buf.len() - 2) {
					return_val = return_val + (buf[i] as char).to_string().as_str();
				}
				return_val.replace("\0", "")
			},
			term: buf[buf.len() - 1],
		};

		dbg!(&packet);

		let mut buf = [0; 32];

		buf[0] = packet.size >> 0;
		buf[1] = packet.size >> 1;
		buf[2] = packet.size >> 2;
		buf[3] = packet.size >> 3;
		
		dbg!(buf);
		
		match packet.ptype {
			0 => {
				println!("rec 0");
			}
			2 => {
				println!("rec 2");

				let response = String::new();

				response.add("rararara");

				stream
					.write_all(&[
						8, 0, 0, 0, /*size*/
						0, 0, 0, 0, /*id*/
						0, 0, 0, 0, /*type*/
						0, 0, 0, 0, 0, 0, 0, 0, /*null terminated string + 8 0 bytes*/
						0, /*final 0 signifying end of packet*/
					])
					.unwrap();

				stream.flush().unwrap();
			}
			3 => {
				println!("rec 3");
				stream
					.write_all(&[
						8, 0, 0, 0, /*size*/
						0, 0, 0, 0, /*id*/
						2, 0, 0, 0, /*type*/
						0, 0, 0, 0, 0, 0, 0, 0, /*null terminated string*/
						0, /*final 0 signifying end of packet*/
					])
					.unwrap();
				stream.flush().unwrap();
			}
			_ => panic!("wtf"),
		}

		// break;
	}
}

fn main2() {
	let (tx, rx) = mpsc::channel();

	let mut proc = std::process::Command::new(
		Path::new("run/terraria/bin/TerrariaServer.bin.x86_64")
			.canonicalize()
			.unwrap(),
	);

	thread::spawn(move || {
		let sockaddr: SocketAddr = "127.0.0.1:49634".parse().expect("invalid ip");
		loop {
			let listener = TcpListener::bind(sockaddr).unwrap();
			let (mut stream, addr) = listener.accept().unwrap();
			let mut buf = String::new();

			stream.read_to_string(&mut buf).unwrap();

			tx.send(buf).unwrap();
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

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
}

fn main() {
	let sockaddr: SocketAddr = "127.0.0.1:49634".parse().expect("invalid ip");

	let listener = TcpListener::bind(sockaddr).unwrap();
	let (mut stream, addr) = listener.accept().unwrap();

	loop {
		println!("listening for packet");
		let mut sized_buf = [0; 4096];
		stream.read(&mut sized_buf).unwrap();
		
		
		
		let received_packet = deserialize_packet(&sized_buf);

		match received_packet.ptype {
			0 => {
				println!("rec 0");
			}
			2 => {
				println!("rec 2");

				let packet = RconPacket {
					size: 11,
					id: received_packet.id,
					ptype: 0,
					body: "HLSW: Thhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhest".to_string(),
				};

				let response_buf = serialize_packet(&packet);
				// dbg!(&response_buf);
				stream.write_all(&response_buf).unwrap();
				stream.flush().unwrap();
			}
			3 => {
				println!("rec 3");

				let packet = RconPacket {
					size: 8,
					id: received_packet.id,
					ptype: 2,
					body: "\0\0\0\0\0\0\0\0".to_string(),
				};

				let response_buf = serialize_packet(&packet);
				stream.write_all(&response_buf).unwrap();
				stream.flush().unwrap();
			}
			_ => panic!("wtf"),
		}
	}
}

fn deserialize_packet(buf: &[u8]) -> RconPacket {
	let deserialized = RconPacket {
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
	};
	dbg!(&deserialized);
	deserialized
}

fn serialize_packet(serialized: &RconPacket) -> Vec<u8> {
	let max_body_size = serialized.body.clone().len() - 1;

	let mut buf = vec![0; max_body_size + 14];

	buf[0] = serialized.size as u8;
	buf[1] = (serialized.size >> 8) as u8;
	buf[2] = (serialized.size >> 16) as u8;
	buf[3] = (serialized.size >> 24) as u8;

	buf[4] = serialized.id as u8;
	buf[5] = (serialized.id >> 8) as u8;
	buf[6] = (serialized.id >> 16) as u8;
	buf[7] = (serialized.id >> 24) as u8;

	buf[8] = serialized.ptype as u8;
	buf[9] = (serialized.ptype >> 8) as u8;
	buf[10] = (serialized.ptype >> 16) as u8;
	buf[11] = (serialized.ptype >> 24) as u8;

	for c in serialized.body.clone().char_indices() {
		buf[c.0 + 12] = c.1 as u8;
	}

	dbg!(&serialized);

	buf
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

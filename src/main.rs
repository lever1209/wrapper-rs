use std::{
	env, fs,
	io::{Read, Write},
	net::{IpAddr, SocketAddr, TcpListener},
	path::PathBuf,
	process::Stdio,
	str::FromStr,
	sync::{mpsc, Arc, Mutex},
	thread,
	time::Duration,
	vec,
};

use clap::{arg, value_parser, ArgAction, ArgMatches, Command};
use config::config::Config;

use crate::config::packet::*;

pub(crate) mod config {

	pub(crate) mod config {
		use std::{
			net::{IpAddr, SocketAddr},
			path::PathBuf,
		};
		// #[derive(Debug)]
		// pub(crate) struct User { // will go unused for now
		// 	pub(crate)password: String,
		// 	pub(crate)command_access: Vec<Command>,
		// }

		// #[derive(Debug)]
		// pub(crate) struct Command {
		// 	pub(crate)name: String,
		// 	// pub(crate)args: Vec<String>, // should go unused for now
		// }

		#[derive(Debug)]
		pub(crate) struct Config {
			pub(crate) bind: SocketAddr,
			pub(crate) admin_password: String,
			pub(crate) bin: PathBuf,
			pub(crate) args: Vec<String>,
			pub(crate) wdir: PathBuf,
			pub(crate) ips: Vec<IpAddr>,
			pub(crate) is_whitelist: bool,
		}
	}

	pub(crate) mod packet {
		#[derive(Debug)]
		pub(crate) struct RconPacket {
			pub(crate) size: i32,
			pub(crate) id: i32,
			pub(crate) ptype: i32,
			pub(crate) body: String,
		}

		pub(crate) fn deserialize_packet(buf: &[u8]) -> RconPacket {
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

			deserialized
		}

		pub(crate) fn serialize_packet(serialized: &RconPacket) -> Vec<u8> {
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

			buf
		}
	}
}

fn handle_config(matches: ArgMatches) -> Config {
	let whitelist_path = matches.get_one::<PathBuf>("whitelist");
	let whitelist_string = match whitelist_path {
		Some(e) => {
			if whitelist_path.unwrap().exists() {
				fs::read_to_string(e).unwrap()
			} else {
				"".to_string()
			}
		}
		None => "".to_string(),
	};
	let blacklist_path = matches.get_one::<PathBuf>("blacklist");
	let blacklist_string = match blacklist_path {
		Some(e) => {
			if blacklist_path.unwrap().exists() {
				fs::read_to_string(e).unwrap()
			} else {
				"".to_string()
			}
		}
		None => "".to_string(),
	};

	let mut ips = vec![];
	let mut is_whitelist = false;

	if blacklist_string.is_empty() && whitelist_string.is_empty() {
	} else if blacklist_string.is_empty() && !whitelist_string.is_empty() {
		ips.append(&mut whitelist_string.split("\n").collect());
		is_whitelist = true;
	} else if !blacklist_string.is_empty() && whitelist_string.is_empty() {
		ips.append(&mut blacklist_string.split("\n").collect());
	} else if !blacklist_string.is_empty() && !whitelist_string.is_empty() {
		ips.append(&mut blacklist_string.split("\n").collect());

		let white_ips: Vec<&str> = whitelist_string.split("\n").collect();
		for (index, ip) in ips.clone().iter().enumerate() {
			if white_ips.contains(&ip) {
				ips.remove(index);
			}
		}
	};

	let ips = {
		let mut ips_return = vec![];

		for ip in ips {
			if ip.is_empty() {
				continue;
			}
			ips_return.push(IpAddr::from_str(ip).unwrap());
		}

		ips_return
	};

	Config {
		bind: if matches.get_one::<SocketAddr>("bind").is_some() {
			*matches.get_one::<SocketAddr>("bind").unwrap()
		} else {
			SocketAddr::new(
				IpAddr::from_str("0.0.0.0").unwrap(),
				*matches.get_one("port").unwrap(),
			)
		},
		admin_password: matches.get_one::<String>("password").unwrap().to_string(),
		bin: matches
			.get_one::<PathBuf>("bin")
			.unwrap()
			.to_path_buf()
			.canonicalize()
			.unwrap(),
		args: matches
			.get_many::<String>("arg")
			.unwrap_or_default()
			.into_iter()
			.map(|x| x.into())
			.collect(),
		wdir: if matches.get_one::<PathBuf>("wdir").is_some() {
			matches.get_one::<PathBuf>("wdir").unwrap().into()
		} else {
			env::current_dir().unwrap()
		}
		.canonicalize()
		.unwrap(),
		ips: ips,
		is_whitelist: is_whitelist,
	}
}

fn main() {
	let root_command = Command::new(env!("CARGO_PKG_NAME"))
		.version(env!("CARGO_PKG_VERSION"))
		.author(env!("CARGO_PKG_AUTHORS"))
		.about(env!("CARGO_PKG_DESCRIPTION"))
		.arg(arg!(-p --port <port> "Port to bind to").conflicts_with("bind").value_parser(value_parser!(u16)).default_value("27015"))
		.arg(arg!(--bind <"address:port"> "Bind value to use: 192.168.2.20:7777").conflicts_with("port").value_parser(value_parser!(SocketAddr)))//.default_value("0.0.0.0:27015"))
		.arg(arg!(-P --password <password> "Admin password").value_parser(value_parser!(String)).required(true))
		.arg(arg!(--whitelist <path> "Whitelist path, newline delimited file of addresses to always allow, even if present in the blacklist").value_parser(value_parser!(PathBuf)))
		.arg(arg!(--blacklist <path> "Blacklist path, newline delimited file of addresses to deny").value_parser(value_parser!(PathBuf)))
		.arg(arg!(-b --bin <path> "Path to the program to execute").value_parser(value_parser!(PathBuf)).required(true))
		.arg(arg!(-a --arg <argument> "Argument to pass to the program, can be used multiple times: -a arg1 -a arg2").value_parser(value_parser!(String)).action(ArgAction::Append))
		.arg(arg!(-w --wdir <path> "Working directory to execute the program in").value_parser(value_parser!(PathBuf)))
		// TODO mode to disable inserting newline at the end of every command, and instead interperet \n as newline and replace it before sending command
		;

	let matches = root_command.get_matches();

	let config = handle_config(matches);

	println!(
		"Spawning process {:?} with args {:?} in wdir {:?} on bind {}",
		config.bin, config.args, config.wdir, config.bind
	);

	let (server_write, server_read) = mpsc::channel();
	let (client_write, client_read) = mpsc::channel();

	// let (recorder_write, recorder_read) = mpsc::channel::<String>();
	// let (recorder_request_record, recorder_respond_record) = mpsc::channel::<()>();

	let mut proc = std::process::Command::new(config.bin.canonicalize().unwrap());

	thread::spawn(move || {
		let sockaddr: SocketAddr = config.bind;

		let listener = TcpListener::bind(sockaddr).unwrap();

		loop {
			let (mut stream, addr) = listener.accept().unwrap();

			if config.is_whitelist {
				if !config.ips.contains(&addr.ip()) {
					stream.shutdown(std::net::Shutdown::Both).ok();
					break;
				}
			} else {
				if config.ips.contains(&addr.ip()) {
					stream.shutdown(std::net::Shutdown::Both).ok();
					break;
				}
			}

			loop {
				let mut sized_buf = [0; 4096];
				stream.read(&mut sized_buf).unwrap();

				let received_packet = deserialize_packet(&sized_buf);

				match received_packet.ptype {
					0 => {
						if sized_buf == [0; 4096] {
							// println!("client exit");
							stream.shutdown(std::net::Shutdown::Both).ok();
							break;
						}
					}

					2 => {
						// println!("rec 2");

						let buf = received_packet.body;
						// stream.read_to_string(&mut buf).unwrap();

						server_write.send(buf.clone()).unwrap();

						let client_body = format!(
							"Server Received Command: {}\n{}\0",
							buf,
							client_read.recv().unwrap()
						);

						let packet = RconPacket {
							size: (9 + client_body.len()) as i32,
							id: received_packet.id,
							ptype: 0,
							body: client_body,
						};

						let response_buf = serialize_packet(&packet);
						stream.write_all(&response_buf).unwrap();
						stream.flush().unwrap();
					}
					3 => {
						let packet = if received_packet.body == config.admin_password {
							RconPacket {
								size: 10,
								id: received_packet.id,
								ptype: 2,
								body: "\0".to_string(),
							}
						} else {
							RconPacket {
								size: 10,
								id: -1,
								ptype: 2,
								body: "\0".to_string(),
							}
						};

						let response_buf = serialize_packet(&packet);
						stream.write_all(&response_buf).unwrap();
						stream.flush().unwrap();
					}
					_ => {
						eprintln!("{}", received_packet.ptype);
						break;
					}
				}
			}
		}
	});

	let proc = proc
		.stdin(Stdio::piped())
		.stderr(Stdio::inherit())
		.stdout(Stdio::inherit())
		.current_dir(config.wdir.canonicalize().unwrap())
		.spawn();

	match proc {
		Ok(mut child) => {
			let mut stdin_pipe = child.stdin.take().expect("could not take stdin");
			// let mut stdout_pipe = Arc::new(Mutex::new(
			// 	child.stdout.take().expect("could not take stdout"),
			// ));
			// let mut stderr_pipe = child.stderr.take().expect("could not take stderr");

			loop {
				match server_read.recv_timeout(Duration::new(1, 0)) {
					Ok(to_write) => {
						/*
						recording thread that constantly prints pipe to stdout, and if request to record, copy to record
							potential bug when multiple commands execute at once? impossible, nature of stdin makes running multiple commands running at once impossible
							potential issue regarding how long to record stdout? SEVERE
								mitigations? permission based password system consisting of multiple "passwords" that are just hashes of passwords saved here, that will be calculated into hashes and compared to incoming hashes
								regex to match final output of command for success and error if error is possible
								timer to limit how long to wait for command to finish on a per command basis
								option to disable returning command output entirely
								use dedicated after command that matches regex to let recorder know to stop recording?
									start and exit commands with originating ip and username when supported to act as splits between commands to help with above

						*/

						// start recording stdout
						stdin_pipe
							.write_all(format!("{}\n", to_write).as_bytes())
							.expect("could not write to stdin of child");
						stdin_pipe.flush().unwrap();
						// stop recording stdout and save to RESPONSE
						client_write.send("RESPONSE").unwrap();
					}
					Err(_) => match child.try_wait() {
						Ok(Some(_)) => break,
						Ok(None) => (),
						Err(e) => eprintln!("{e}"),
					},
				}
			}
		}
		Err(e) => eprintln!("proc failed to start: {e}"),
	}
}

use std::{
	collections::HashMap,
	hash::Hash,
	io::{Read, Write},
	net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener},
	path::PathBuf,
	process::Stdio,
	sync::{
		mpsc::{self, Receiver, Sender},
		Arc, Mutex,
	},
	thread,
	time::Duration,
};

use clap::{arg, value_parser, ArgAction, Command};

use crate::{
	config::packet::{deserialize_packet, serialize_packet, RconPacket},
	messenger::{ChildReadRequest, ChildReadResponse, ServerCommandRequest, ServerCommandResponse},
};

pub(crate) mod config {
	// FIXME messy as all hell in here
	use std::{
		env, fs,
		net::{IpAddr, SocketAddr},
		path::PathBuf,
		str::FromStr,
	};

	use clap::ArgMatches;

	use self::config::Config;

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

	pub(crate) fn handle_config(matches: ArgMatches) -> Config {
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
}

pub(crate) mod messenger {
	use std::net::IpAddr;
	#[derive(Debug)]
	pub(crate) struct ChildReadRequest {
		pub(crate) command: String,
		pub(crate) ip: IpAddr,
	}
	#[derive(Debug)]
	pub(crate) struct ChildReadResponse {
		pub(crate) body: String,
	}

	#[derive(Debug)]
	pub(crate) struct ServerCommandRequest {
		pub(crate) command: String,
		pub(crate) ip: IpAddr,
	}
	#[derive(Debug)]
	pub(crate) struct ServerCommandResponse {
		pub(crate) command: String,
		pub(crate) ip: IpAddr,
		pub(crate) body: String,
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
		.arg(arg!(-a --arg <argument> "Argument to pass to the program, can be used multiple times: -a arg1 -a arg2").value_parser(value_parser!(String)).action(ArgAction::Append).allow_hyphen_values(true))
		.arg(arg!(-w --wdir <path> "Working directory to execute the program in").value_parser(value_parser!(PathBuf)))
		// TODO mode to disable inserting newline at the end of every command, and instead interperet \n as newline and replace it before sending command
		;

	let matches = root_command.get_matches();

	let config = config::handle_config(matches);

	println!(
		"Spawning process {:?} with args {:?} in wdir {:?} on bind {}",
		config.bin, config.args, config.wdir, config.bind
	);

	let command_request = mpsc::channel();
	let command_response: (
		// requires manually assigning types for some odd reason
		Sender<ServerCommandResponse>,
		Receiver<ServerCommandResponse>,
	) = mpsc::channel();

	let child_read_request = mpsc::channel();
	// let child_read_response = mpsc::channel();

	{
		child_read_request
			.0
			.send(ChildReadRequest {
				command: "uwu".to_string(),
				ip: Ipv4Addr::new(0, 0, 0, 0).into(),
			})
			.unwrap();

		dbg!(child_read_request.1.recv().unwrap());

		// child_read_response
		// 	.0
		// 	.send(ChildReadResponse {
		// 		body: "uwu".to_string(),
		// 	})
		// 	.unwrap();

		// dbg!(child_read_response.1.recv().unwrap());
	}

	let mut proc = std::process::Command::new(config.bin.canonicalize().unwrap());

	let proc = proc
		.stdin(Stdio::piped())
		.stderr(Stdio::piped())
		.stdout(Stdio::piped())
		.current_dir(config.wdir.canonicalize().unwrap())
		.args(config.args)
		.spawn();

	match proc {
		Ok(mut child) => {
			let mut stdin_pipe = child.stdin.take().expect("could not take stdin");
			let mut stdout_pipe = child.stdout.take().expect("could not take stdout");
			let connected_clients: Arc<Mutex<HashMap<(IpAddr, String), String>>> =
				Arc::new(Mutex::new(HashMap::new()));

			// let console_lines: Arc<Mutex<Vec<char>>> = Arc::new(Mutex::new(vec![]));

			// TODO thread to send empty packets to running command senders

			let connected_clients_t01 = connected_clients.clone();

			thread::spawn(move || {
				let mut string_buffer = String::new();
				let mut response_string_buffer = String::new();
				loop {
					let bs = stdout_pipe.by_ref().bytes();

					for b in bs {
						let b = b.unwrap() as char;
						string_buffer.push(b);

						if b == '\n' {
							// console_lines.lock().unwrap().push(b);
							print!("{}", string_buffer);
							// TODO ip verification with ((^\s*((([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))\s*$)|(^\s*((([0-9A-Fa-f]{1,4}:){7}([0-9A-Fa-f]{1,4}|:))|(([0-9A-Fa-f]{1,4}:){6}(:[0-9A-Fa-f]{1,4}|((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){5}(((:[0-9A-Fa-f]{1,4}){1,2})|:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){4}(((:[0-9A-Fa-f]{1,4}){1,3})|((:[0-9A-Fa-f]{1,4})?:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){3}(((:[0-9A-Fa-f]{1,4}){1,4})|((:[0-9A-Fa-f]{1,4}){0,2}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){2}(((:[0-9A-Fa-f]{1,4}){1,5})|((:[0-9A-Fa-f]{1,4}){0,3}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){1}(((:[0-9A-Fa-f]{1,4}){1,6})|((:[0-9A-Fa-f]{1,4}){0,4}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(:(((:[0-9A-Fa-f]{1,4}){1,7})|((:[0-9A-Fa-f]{1,4}){0,5}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:)))(%.+)?\s*$))
							if regex::Regex::new(".*RCON_COMMAND_START\\[.+\\]\\[.+\\].*")
								.unwrap()
								.is_match(&string_buffer)
							{
								// println!("START MATCH");

								let command = {
									let mut command = String::new();

									let base = "RCON_COMMAND_START".as_bytes();
									let mut index = 0;

									for c in string_buffer.char_indices() {
										// println!("{}", base[i + correct] as char);

										if index >= base.len() {
											// index = 0;

											let mut is_recording = false;

											for cc in c.0..string_buffer.len() - 1 {
												let cc = string_buffer.as_bytes()[cc] as char;
												// println!("{}", cc);

												if cc == ']' {
													break;
												}

												if is_recording {
													command.push(cc);
												}

												if cc == '[' {
													is_recording = true;
												}
											}

											break;
										} else if base[index] as char == c.1 {
											index += 1;
										}
									}
									command
								};
								
								let ip = {
									let mut ip = String::new();

									let base = "RCON_COMMAND_START".as_bytes();
									let mut index = 0;

									for c in string_buffer.char_indices() {
										// println!("{}", base[i + correct] as char);

										if index >= base.len() {
											// index = 0;

											let mut is_recording = false;

											for cc in c.0..string_buffer.len() - 1 {
												let cc = string_buffer.as_bytes()[cc] as char;
												// println!("{}", cc);

												if cc == ']' {
													break;
												}

												if is_recording {
													ip.push(cc);
												}

												if cc == '[' {
													is_recording = true;
												}
											}

											break;
										} else if base[index] as char == c.1 {
											index += 1;
										}
									}
									ip
								};

								println!("CCMD: {}, IP: {}", command, ip);
							} else if regex::Regex::new(".*RCON_COMMAND_END\\[.+\\]\\[.+\\]")
								.unwrap()
								.is_match(&string_buffer)
							{
								println!("END MATCH");
							}

							string_buffer.clear();
						}
					}
				}
			});

			thread::spawn(move || loop {
				let read_request = child_read_request.1.recv().unwrap();
				let mut connected_clients = connected_clients_t01.lock().unwrap();
				connected_clients.insert(
					(read_request.ip, read_request.command.clone()),
					String::new(),
				);

				thread::sleep(Duration::new(4, 0));

				connected_clients.insert(
					(read_request.ip, read_request.command),
					"some shit".to_string(),
				);
			});

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

								let command_request_struct = ServerCommandRequest {
									command: buf.clone(),
									ip: addr.ip(),
								};

								command_request.0.send(command_request_struct).unwrap();

								let client_body = format!(
									"Server Received Command: {}\nResponse:\n{}\0",
									buf,
									command_response.1.recv().unwrap().body
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

			loop {
				match command_request.1.recv_timeout(Duration::new(1, 0)) {
					Ok(command_request) => {
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

						println!(); // to prevent strange logging in host

						child_read_request
							.0
							.send(ChildReadRequest {
								command: command_request.command.clone(),
								ip: command_request.ip,
							})
							.unwrap();

						stdin_pipe
							.write_all(format!("say RCON_COMMAND_START[{0}][{1}]\n{0}\nsay RCON_COMMAND_END[{0}][{1}]\n", command_request.command, command_request.ip).as_bytes()) // TODO make configurable start/stop commands
							.expect("could not write to stdin of child");
						stdin_pipe.flush().unwrap();

						let response = {
							let response;
							loop {
								let mut clients = connected_clients.lock().unwrap();

								if clients.contains_key(&(
									command_request.ip,
									command_request.command.clone(),
								)) && !clients
									.get(&(command_request.ip, command_request.command.clone()))
									.unwrap()
									.is_empty()
								{
									response = clients
										.get(&(command_request.ip, command_request.command.clone()))
										.unwrap()
										.to_string();
									dbg!(&clients);
									clients.remove_entry(&(
										command_request.ip,
										command_request.command.clone(),
									));
									break;
								}
							}
							response
						};

						command_response
							.0
							.send(ServerCommandResponse {
								body: response,
								ip: command_request.ip,
								command: command_request.command,
							})
							.unwrap();
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

use std::{
    io::{Read, Write},
    net::{SocketAddr, TcpListener, TcpStream},
};

use clap::Parser;
use paillier::*;

fn _main() {
    // generate a fresh keypair and extract encryption and decryption keys
    let (ek, dk) = Paillier::keypair().keys();

    // encrypt four values
    let c1 = Paillier::encrypt(&ek, 10);
    let c2 = Paillier::encrypt(&ek, 20);
    let c3 = Paillier::encrypt(&ek, 30);
    let c4 = Paillier::encrypt(&ek, 40);

    // add all of them together
    let c = Paillier::add(
        &ek,
        &Paillier::add(&ek, &c1, &c2),
        &Paillier::add(&ek, &c3, &c4),
    );

    // multiply the sum by 2
    let d = Paillier::mul(&ek, &c, 2);

    // decrypt final result
    let m: u64 = Paillier::decrypt(&dk, &d);
    println!("decrypted total sum is {}", m);
}

/// Command line argument
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Wether or not we are the master server
    #[arg(short, long)]
    master: bool,

    /// Socket address of the next server in the chain
    #[arg(short, long)]
    next: SocketAddr,

    /// Socket address to listen on
    #[arg(short, long)]
    bind: SocketAddr,

    /// Number to add
    #[arg(long)]
    add: BigInt,

    /// Number to multiply by
    #[arg(long)]
    mul: BigInt,
}

fn send(
    addr: SocketAddr,
    encryption_key: &EncryptionKey,
    cyphertext: &BigInt,
) -> anyhow::Result<()> {
    println!("connecting to {:?}", addr);
    let mut socket = TcpStream::connect(addr)?;

    let encoded_cyphertext = cyphertext.to_str_radix(16);

    socket.write_all(&(encoded_cyphertext.len() as u64).to_le_bytes())?;
    socket.write_all(encoded_cyphertext.as_bytes())?;
    serde_json::to_writer(socket, encryption_key)?;

    Ok(())
}

fn recv(addr: SocketAddr) -> anyhow::Result<(EncryptionKey, BigInt)> {
    println!("listening on {:?}", addr);
    let (mut socket, remote_addr) = TcpListener::bind(addr)?.accept()?;
    println!("connection from {remote_addr:?}");

    let mut len = [0u8; 8];
    socket.read_exact(&mut len)?;
    let len: usize = u64::from_le_bytes(len).try_into()?;

    let mut buffer = vec![0; len];
    socket.read_exact(&mut buffer)?;
    let encoded_cyphertext = std::str::from_utf8(&buffer)?;
    let cyphertext = BigInt::from_str_radix(encoded_cyphertext, 16)?;

    let ek: EncryptionKey = serde_json::from_reader(socket)?;

    Ok((ek, cyphertext))
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    let mut decryption_key = None;

    if args.master {
        let (ek, dk) = Paillier::keypair().keys();
        decryption_key = Some(dk);

        let plaintext: RawPlaintext = BigInt::from(args.add.clone() * &args.mul).into();
        let cyphertext = Paillier::encrypt(&ek, plaintext);

        send(args.next, &ek, &cyphertext.0)?;
    }

    let (ek, cyphertext) = recv(args.bind)?;
    let cyphertext = RawCiphertext::from(cyphertext);

    if let Some(dk) = decryption_key {
        assert!(args.master);

        let plaintext = Paillier::decrypt(&dk, cyphertext).0;

        println!("The result is {plaintext}");
    } else {
        let add = Paillier::encrypt(&ek, RawPlaintext::from(args.add.clone()));
        let mul = RawPlaintext::from(args.mul.clone());

        let cyphertext = Paillier::add(&ek, cyphertext, add);
        let cyphertext = Paillier::mul(&ek, cyphertext, mul);

        send(args.next, &ek, &cyphertext.0)?;
    }

    Ok(())
}

use std::str::FromStr;

use clap::{Parser, command};
use postcard::fixint::le;
use rand::seq::SliceRandom;
use rand::rngs::SysRng;
use crate::cipher_data::CipherData;

mod cipher_data;
mod error;
#[derive(Debug,Clone)]
enum Mode {
    Encrypt,
    Decrypt,
}

impl FromStr for Mode {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "e" => Ok(Mode::Encrypt),
            "d" => Ok(Mode::Decrypt),
            _ => Err(format!("Invalid mode: {}", s)),
        }
    }
}
#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct VailArgs{
    #[arg(short, long, value_parser = clap::value_parser!(Mode))]
    mode: Mode,
    #[arg(short, long)]
    data_path: Option<String>,
    #[arg(short, long)]
    input: String,
}
#[cfg(test)]
mod tests{
    use rand::rngs::SysRng;

    use crate::cipher_data::CipherData;

    #[test]
    fn test(){
        let text = "Hello, World!";
        let mut rng =SysRng::default();
        let cipher_data = CipherData::new(&mut rng, None).unwrap();
        let encrypted = cipher_data.encrypt_blocks(text, &mut rng);  
        let decrypted = cipher_data.decrypt_blocks(&encrypted);
        assert_eq!(text, decrypted);
    }
}

fn main() {
    let mut rng =SysRng::default();
    let args = VailArgs::parse();
    match (args.mode,args.data_path) {
        (Mode::Encrypt,  data_path) => {
            let cipher_data = CipherData::new(&mut rng, data_path).unwrap();
            let cipher_text = cipher_data.encrypt_blocks(&args.input,&mut rng);
            println!("{}", cipher_text);
        },
        (Mode::Decrypt,  data_path) => {
            let cipher_data = CipherData::new(&mut rng, data_path).unwrap();
            let plain_text = cipher_data.decrypt_blocks(&args.input);
            println!("{}", plain_text);
        },
        _ => {
            println!("Invalid arguments. Please provide mode and input.");
        }
    }
}

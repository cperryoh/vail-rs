use std::{
    char,
    collections::HashMap,
    fs::{self, read},
};

use error::Result;
use base64::{engine::general_purpose, Engine as _};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{ error, util};
use rand::{SeedableRng, TryRng, rngs::{StdRng, SysRng}};
const CHAR_SPACE: [char; 79] = [
    'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's',
    't', 'u', 'v', 'w', 'x', 'y', 'z', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L',
    'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', ',', '.', '?', '&', '%',
    '!', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '/', ':', ';', '=', '<', '>', '#', '~',
    '^', '_', '@',
];
const POSSIBLE_SPACE_MAPPINGS: [char; 4] = ['~', '^', '_', '@'];
#[derive(Serialize, Deserialize, Debug)]
pub struct CipherData {
    levels: HashMap<String, i32>,
    mix_ups: HashMap<String, HashMap<char, char>>,
    reverse_mix_ups: HashMap<String, HashMap<char, char>>,
    level_keys: Vec<String>,
    mixup_keys: Vec<String>,
    space_mapping: char,
    div_mapping: char,
    data_id:[u8;32] 
}
impl CipherData {
    fn from_file(file_path: &str) -> Result<CipherData> {
        let bytes = read(file_path)?;
        let data = postcard::from_bytes::<CipherData>(&bytes)?;
        Ok(data)
    }
    fn write_to_disk(&self, file_path: &str) -> Result<()> {
        let bytes = postcard::to_allocvec(self)?;
        fs::write(file_path, bytes)?;
        Ok(())
    }
    pub fn remove_cipher(&self, cipher_text: &str) -> String {
        let cut_string = cipher_text[3..].to_string();
        let key = cipher_text.chars().take(3).collect::<String>();
        let mixup = self
            .reverse_mix_ups
            .get(&key)
            .unwrap_or_else(|| panic!("Mixup not found for key {key}"));
        let cut_string: String = cut_string
            .chars()
            .map(|c| if c == ' ' { c } else { *mixup.get(&c).unwrap() })
            .collect();
        cut_string
    }
    pub fn decrypt_cipher(&self, cipher_text: &str,secret: &str) -> String {
        let (nonce_base64, cipher_text) = cipher_text.split_once('+').expect("Invalid cipher text format");
        let nonce_bytes = general_purpose::STANDARD.decode(nonce_base64).expect("Invalid nonce encoding");
        let seed = self.derive_seed(&nonce_bytes,secret);
        let level_val:u32= u32::from_be_bytes(seed[0..4].try_into().unwrap());
        let level_key = &self.level_keys[level_val as usize% self.level_keys.len()];

        let mixup_val:u32= u32::from_be_bytes(seed[4..8].try_into().unwrap());
        let mixup_key = &self.mixup_keys[mixup_val as usize % self.mixup_keys.len()];
        let mixup = self.reverse_mix_ups.get(mixup_key).unwrap();
        let cipher_text = cipher_text.chars().map(|c| if c == self.space_mapping { ' ' } else { *mixup.get(&c).unwrap() }).collect::<String>();

        let level = self.levels.get(level_key).unwrap();
        let cut_string = cipher_text[2..].to_string();
        let mut out = cut_string;
        for _ in 0..*level {
            out = self.remove_cipher(&out);
        }
        out
    }
    pub fn encrypt_blocks(&self, plain_text: &str, secret: &str) -> String {
        let plain_blocks: Vec<String> = plain_text
            .chars()
            .collect::<String>()
            .chars()
            .collect::<Vec<char>>()
            .chunks(10)
            .map(|chunk| chunk.iter().collect())
            .collect();
        let encrypted_blocks: Vec<String> = plain_blocks
            .iter()
            .map(|block| self.encrypt_cipher(block, secret))
            .collect();
        encrypted_blocks.join(self.div_mapping.to_string().as_str())
    }
    pub fn decrypt_blocks(&self, cipher_text: &str,secret: &str) -> String {
        let cipher_blocks: Vec<String> = cipher_text
            .chars()
            .collect::<String>()
            .split(self.div_mapping.to_string().as_str())
            .map(|s| s.to_string())
            .collect();
        let decrypted_blocks: Vec<String> = cipher_blocks
            .iter()
            .map(|block| self.decrypt_cipher(block,secret))
            .collect();
        decrypted_blocks.join("")
    }

    fn derive_seed(&self, nonce: &[u8],secret: &str) -> [u8;32] {

        // Replace this with whatever stable secret material you want from .dat
        let mut hasher:Sha256= Digest::new();
        

        // Public nonce
        hasher.update(&self.data_id);
        hasher.update(nonce);
        hasher.update(secret.as_bytes());

        let digest = hasher.finalize();

        let mut seed = [0u8; 32];
        seed.copy_from_slice(&digest);
        seed
    }

    pub fn encrypt_cipher(&self, plain_text: &str,secret: &str) -> String {
        let mut nonce = [0u8; 12];
        let plain_text:String = plain_text.chars().map(|c| if c==' ' {self.space_mapping} else {c}).collect();
        let mut rng = SysRng;
        rng.try_fill_bytes(&mut nonce).expect("Failed to make nonce");
        let seed = self.derive_seed(&nonce,secret);
        let mut rng = StdRng::from_seed(seed);
        let level_val:u32= u32::from_be_bytes(seed[0..4].try_into().unwrap());
        let mixup_val:u32= u32::from_be_bytes(seed[4..8].try_into().unwrap());

        let plain_text = plain_text.chars().collect::<String>();
        let level_key = &self.level_keys[level_val as usize% self.level_keys.len()];
        let level = self.levels.get(level_key).unwrap();
        let mut out = plain_text.to_string();
        for _ in 0..*level {
            out = self.add_cipher(&out, &mut rng);
        }
        let last_mixup_index = mixup_val as usize % self.mixup_keys.len();
        let last_mixup_key = &self.mixup_keys[last_mixup_index];
        let last_mixup = self.mix_ups.get(last_mixup_key).unwrap();
        out = format!("{}{}", level_key, out);
        out = out.chars().map(|c| if c == self.space_mapping { c } else { *last_mixup.get(&c).unwrap() }).collect();
        format!("{}+{}", general_purpose::STANDARD.encode(nonce), out)
    }
    pub fn add_cipher(&self, plain_text: &str, rng: &mut StdRng) -> String {
        let key = util::choose::<String>(&self.mixup_keys, rng);
        let mixup = self.mix_ups.get(&key).unwrap();
        let cipher_text: String = plain_text
            .chars()
            .map(|c| {
                if c == self.space_mapping {
                    c
                } else {
                    *mixup
                        .get(&c)
                        .unwrap_or_else(|| panic!("Character not found in mixup {c}"))
                }
            })
            .collect();
        format!("{}{}", key, cipher_text)
    }
    pub fn new(rng: &mut SysRng, data_path: Option<String>) -> Result<Self> {
        let resolved_path = data_path.as_deref().unwrap_or("data.dat");
        if std::fs::exists(resolved_path)? {
            return Self::from_file(resolved_path);
        }
        let space_mapping = util::choose(&POSSIBLE_SPACE_MAPPINGS, rng);
        let possible_div_mappings: Vec<char> = POSSIBLE_SPACE_MAPPINGS
            .iter()
            .filter(|c| **c != space_mapping)
            .cloned()
            .collect();
        let div_mapping = util::choose(&possible_div_mappings, rng);
        let mut id:[u8;32] = [0u8;32];
        rng.try_fill_bytes(&mut id).expect("Failed to make ID");
        let mut data = Self {
            levels: HashMap::new(),
            mix_ups: HashMap::new(),
            reverse_mix_ups: HashMap::new(),
            level_keys: Vec::new(),
            mixup_keys: Vec::new(),
            space_mapping,
            div_mapping,
            data_id: id,
        };
        let adjusted_char_space: Vec<char> = CHAR_SPACE
            .iter()
            .filter(|c| !(**c == space_mapping || **c == div_mapping))
            .cloned()
            .collect();
        for _ in 0..100 {
            let key = util::make_key(3, &adjusted_char_space, rng);
            let mut mixup: Vec<char> = adjusted_char_space.to_vec();
            util::shuffle(&mut mixup, rng);
            let mut mixup_map: HashMap<char, char> = HashMap::new();
            let mut reverse_mixup_map: HashMap<char, char> = HashMap::new();
            for i in 0..adjusted_char_space.len() {
                let c = adjusted_char_space[i];
                let m = mixup[i];
                mixup_map.insert(c, m);
                reverse_mixup_map.insert(m, c);
            }
            data.mix_ups.insert(key.clone(), mixup_map);
            data.reverse_mix_ups.insert(key.clone(), reverse_mixup_map);
            data.mixup_keys.push(key);
        }

        for _ in 0..10 {
            let key = util::make_key(2, &adjusted_char_space, rng);
            let i = util::range(10, 20, rng);
            data.levels.insert(key.clone(), i);
            data.level_keys.push(key);
        }
        data.write_to_disk(resolved_path)?;

        Ok(data)
    }
}

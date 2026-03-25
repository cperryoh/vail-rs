use std::{
    char,
    collections::HashMap,
    fs::{self, read},
};

use error::Result;
use serde::{Deserialize, Serialize};

use crate::{error, util};
use rand::{TryRng, distr::Open01, rngs::SysRng};
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
}
impl CipherData {
    fn from_file(file_path: &str) -> Result<CipherData> {
        let bytes = read(file_path)?;
        let data = postcard::from_bytes::<CipherData>(&bytes)?.into();
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
    pub fn decrypt_cipher(&self, cipher_text: &str) -> String {
        let level_key = cipher_text.chars().take(2).collect::<String>();
        let level = self.levels.get(&level_key).unwrap();
        let cut_string = cipher_text[2..].to_string();
        let mut out = cut_string;
        for _ in 0..*level {
            out = self.remove_cipher(&out);
        }
        out
    }
    pub fn encrypt_blocks(&self, plain_text: &str, rand: &mut SysRng) -> String {
        let plain_blocks: Vec<String> = plain_text
            .chars()
            .map(|c| if c == ' ' { self.space_mapping } else { c })
            .collect::<String>()
            .chars()
            .collect::<Vec<char>>()
            .chunks(10)
            .map(|chunk| chunk.iter().collect())
            .collect();
        let encrypted_blocks: Vec<String> = plain_blocks
            .iter()
            .map(|block| self.encrypt_cipher(block, rand))
            .collect();
        encrypted_blocks.join(self.div_mapping.to_string().as_str())
    }
    pub fn decrypt_blocks(&self, cipher_text: &str) -> String {
        let cipher_blocks: Vec<String> = cipher_text
            .chars()
            .map(|c| if c == self.space_mapping { ' ' } else { c })
            .collect::<String>()
            .split(self.div_mapping.to_string().as_str())
            .map(|s| s.to_string())
            .collect();
        let decrypted_blocks: Vec<String> = cipher_blocks
            .iter()
            .map(|block| self.decrypt_cipher(block))
            .collect();
        decrypted_blocks.join("")
    }
    pub fn encrypt_cipher(&self, plain_text: &str, rand: &mut SysRng) -> String {
        let plain_text = plain_text.chars().collect::<String>();
        let level_key = util::choose::<String>(&self.level_keys, rand);
        let level = self.levels.get(&level_key).unwrap();
        let mut out = plain_text.to_string();
        for _ in 0..*level {
            out = self.add_cipher(&out, rand);
        }
        format!("{}{}", level_key, out)
    }
    pub fn add_cipher(&self, plain_text: &str, rng: &mut SysRng) -> String {
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
        if std::fs::exists(&resolved_path)? {
            return Ok(Self::from_file(&resolved_path)?);
        }
        let space_mapping = util::choose(&POSSIBLE_SPACE_MAPPINGS, rng);
        let possible_div_mappings: Vec<char> = POSSIBLE_SPACE_MAPPINGS
            .iter()
            .filter(|c| **c != space_mapping)
            .cloned()
            .collect();
        let div_mapping = util::choose(&possible_div_mappings, rng);
        let mut data = Self {
            levels: HashMap::new(),
            mix_ups: HashMap::new(),
            reverse_mix_ups: HashMap::new(),
            level_keys: Vec::new(),
            mixup_keys: Vec::new(),
            space_mapping: space_mapping,
            div_mapping: div_mapping,
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
        data.write_to_disk(&resolved_path)?;

        Ok(data)
    }
}

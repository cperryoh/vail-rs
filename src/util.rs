use rand::{TryRng, rngs::SysRng};


pub fn make_key(len: usize, adjusted_char_space: &[char], rng: &mut SysRng) -> String {
    let mut key: Vec<char> = Vec::with_capacity(len);
    for _ in 0..len {
        let index: usize =
            range(0, adjusted_char_space.len().try_into().unwrap(), rng) as usize;
        let c = adjusted_char_space[index];
        key.push(c);
    }
    key.into_iter().collect()
}
pub fn shuffle<T>(vec: &mut Vec<T>, rng: &mut SysRng) {
    for i in (1..vec.len()).rev() {
        let j = range(0, vec.len().try_into().unwrap(), rng) as usize;
        vec.swap(i, j);
    }
}
pub fn range(start: i32, end: i32, rng: &mut SysRng) -> i32 {
    let range = end - start;
    let num = rng.try_next_u32().unwrap() % (range as u32);
    start + num as i32
}
pub fn choose<T: Clone>(vec: &[T], rng: &mut SysRng) -> T {
    let index = range(0, vec.len() as i32, rng) as usize;
    vec[index].clone()
}

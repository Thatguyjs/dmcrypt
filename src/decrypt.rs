use libaes::Cipher;
use sha1::{Sha1, Digest};


// Ported from the python version, XOR's two groups of hex values 5 times
fn multi_xor(values: Vec<&[u8]>, modifier: usize) -> Vec<Vec<u8>> {
    let mut values: Vec<Vec<u8>> = values.iter().map(|s| s.to_vec()).collect();

    for i in 0..5 {
        let pair = (&values[(modifier + i) % 5], &values[i]);
        let group: Vec<u8> = pair.0.iter().zip(pair.1.iter()).map(|(x, y)| x ^ y).collect();

        values[i] = group;
    }

    values
}


// Extracts data needed for decryption from the file header
// Returns a tuple: (flock, iv, encrypted_data)
pub fn extract_header(data: &[u8]) -> Result<(&str, &[u8], &[u8]), &'static str> {
    const FLOCK_START: usize = 12;
    const POST_FLOCK_LEN: usize = 284; // Length of the rest of the header after the flock

    if &data[0..2] != &[1, 9] {
        return Err("Invalid file header");
    }

    // Extract the flock (on first lineof file, looks like an email address; leave out the
    // "lge/flock" part)
    let flock_len = data[2] as usize;
    let flock = std::str::from_utf8(&data[FLOCK_START..FLOCK_START + flock_len])
        .map_err(|_| "Error decoding flock string")?;

    // Skip all header keys; they're not necessary for decryption. Instead, read the next 16 bytes
    // because it's used as the IV for the cipher
    let iv_start = FLOCK_START + flock_len + POST_FLOCK_LEN;
    let iv = &data[iv_start..iv_start + 16];

    Ok((flock, iv, &data[iv_start + 16..]))
}


// Generates the decryption key using the user's email address and the flock from the header
pub fn generate_key(email: &str, flock: &str) -> Vec<u8> {
    let mut hasher = Sha1::new();
    hasher.update(email.as_bytes());

    // Avoids code repitition
    #[inline]
    fn transform_hash(hash: &[u8], modifier: usize) -> Vec<u8> {
        let words: Vec<&[u8]> = (0..5).map(|i| &hash[i * 4..i * 4 + 4]).collect();
        multi_xor(words, modifier).into_iter().flatten().collect::<Vec<u8>>()
    }

    let h1_hash = hasher.finalize();
    let h1 = transform_hash(h1_hash.as_slice(), 2);

    let mut hasher = Sha1::new();
    hasher.update(h1);

    let h2_hash = hasher.finalize();
    let h2 = transform_hash(h2_hash.as_slice(), 4);

    let mut h3 = h2[..16].to_vec();
    h3.extend_from_slice(flock.as_bytes());

    let mut hasher = Sha1::new();
    hasher.update(h3);

    hasher.finalize()[..16].to_vec()
}


// Decrypt multimedia data using header info & the generated key
pub fn decrypt_data(key: &[u8], iv: &[u8], data: &[u8]) -> Result<Vec<u8>, &'static str> {
    if key.len() != 16 {
        return Err("Invalid key length");
    }

    let cipher = Cipher::new_128(key.try_into().unwrap());
    Ok(cipher.cbc_decrypt(iv, data))
}

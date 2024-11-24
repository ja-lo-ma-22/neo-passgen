// converts a seed string into a hashed password string in base94.
//
// summary:
// seed string -> sha512sum -> base94cli -> password

// is used to collect a seed String from the user.
use std::io;

// SHA512sum hashes binary data
use sha2::{Sha512, Digest};

// Base94 converts data to base94
use base94::encode;

fn main() {

    // a mutable String that the seed is stored in.
    let mut seed = String::new();

    // collects the String data from the user and processes potential errors.
    io::stdin()
        .read_line(&mut seed)
        .expect("Failed to read seed.");

    // creates a hash object to process data.
    let mut hasher = Sha512::new();

    // inputs seed data
    hasher.update(& seed);

    // processes the hash and consumes the hasher object
    let seed = hasher.finalize();

    // encodes the hashed_seed in base94
    let seed = encode(& seed, 94);
    
    println!("{}", seed);
}

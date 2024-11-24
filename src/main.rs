// converts a seed string into a hashed password string in base94.
//
// summary:
// seed string -> sha512 -> base94 -> password

// collects a seed String from the user
use std::io;

// reads command-line arguments from the user
use std::env;

// SHA512 hashes binary data
use sha2::{Sha512, Digest};

// Base94 converts data to base94 String
use base94::encode;

fn main() {

    // a mutable String that the seed is stored in.
    let mut seed = String::new();

    // collects command-line arguments into a vector
    let args: Vec<String> = env::args().collect();

    // values for later use in the program
    let mut testing: bool = false;
    let mut program_name = String::new();

    // iterates on the vector of command line arguments
    for argument in args {
        match argument.as_str() {
            "testing" => { testing = true; }
            _ => {
                if program_name.is_empty() {
                    program_name = String::from(argument);
                } else {
                    panic!("{} is not a valid argument.", argument);
                }
            }
        }
    }

    // collects the String data from the user and processes potential errors.
    io::stdin()
        .read_line(&mut seed)
        .expect("Failed to read seed.");

    // creates a hash object to process data.
    let mut hasher = Sha512::new();

    // inputs seed data
    hasher.update(& seed);

    // processes the hash and consumes the hasher object.
    let seed = hasher.finalize();

    // encodes the hashed_seed in base94
    let seed = encode(& seed, 94);
    
    println!("{}", seed);
}

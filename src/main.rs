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

    // Removes trailing '/n' newline character.
    seed.pop();

    // Calls the function and recieves a value.
    let seed = hash_and_base94(seed);
    
    // Prints the final seed to the command line for the user.
    println!("{}", seed);
}



fn hash_and_base94(seed: String) -> String {
    // Creates hash object to process the seed.
    let mut hasher = Sha512::new();

    // Inputs the seed into the hash object.
    hasher.update(& seed);

    // Processes the seed and outputs the final hash in binary.
    let seed = hasher.finalize();

    // Encodes the binary hash as a Base94 String.
    let seed = encode(& seed, 94);

    // Returns the final Base94 String.
    seed
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_test() {
        let comparitor = String::from("=tD-,fsd#3N2+UyWOBhGeq_H|{`arN'~BIi!6fN4t:$s4goerLV40uewQ&#c9DzGV*e3obd&Y#[-4R");
        let output = hash_and_base94(String::from("testing"));
        assert_eq!(output, comparitor);
    }
}

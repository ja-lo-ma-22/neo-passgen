// converts a seed string into a hashed password string in base94.
//
// summary:
// seed string -> sha512 -> base94 -> password

// collects a seed String from the user
use std::io;

// reads command-line arguments from the user
use std::env;

// Used for the exit() function.
use std::process;

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
    let mut password_length: i32 = 0;
    let mut program_name = String::new();
    let mut getlength = false;

    // iterates on the vector of command line arguments
    for argument in args {
        match argument.as_str() {

            // Displays the help() text when matched.
            "help" => { help(); }

            // Gets the next argument as password_length.
            "length" => { getlength = true; }

            // Tests for password_length and handles errors.
            _ => {
                // Captures the program name.
                if program_name.is_empty() {
                    program_name = String::from(argument);

                // Tests the password_length and saves it.
                } else if password_length == 0 && getlength == true {
                    match argument.parse::<i32>() {

                        // Sets the password_length when Okay.
                        Ok(n) => {
                            password_length = n;
                            getlength = false;
                        },

                        // Panics when the String can't be parsed into an i32.
                        Err(e) => { panic!("{}. That is not a valid integer.", e); }
                    }
                } else {
                    panic!("{} is not a valid argument.", argument);
                }
            }
        }
    }

    if password_length == 0 {
        password_length = 32;
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

fn help() {
    println!("The help message is not yet implemented. Good luck.");
    process::exit(0);
}


#[cfg(test)]
mod tests {
    use super::*;

    // Tests that the hashing function produces the correct ouput
    // for a given input.
    #[test]
    fn hash_test() {
        let comparitor = String::from("=tD-,fsd#3N2+UyWOBhGeq_H|{`arN'~BIi!6fN4t:$s4goerLV40uewQ&#c9DzGV*e3obd&Y#[-4R");
        let output = hash_and_base94(String::from("testing"));
        assert_eq!(output, comparitor);
    }
}

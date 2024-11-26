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

    // Sends the command-line arguments to a function to process, and returns an easy Vec<String> to parse.
    let args = process_args(args);

    // List of values from process_args() :
    // [0] = program_name
    // [1] = password_length

    // collects the String data from the user and processes potential errors.
    io::stdin()
        .read_line(&mut seed)
        .expect("Failed to read seed.");

    // Removes trailing '/n' newline character.
    seed.pop();

    // Calls the function and recieves a value.
    let seed = hash_and_base94(seed, args.get(1).unwrap().parse::<i32>().unwrap());
    
    // Prints the final seed to the command line for the user.
    println!("{}", seed);
}

// Accepts a seed and hashes it. Then outputs a String of the
// has in Base94.
fn hash_and_base94(seed: String, length: i32) -> String {
    // Creates hash object to process the seed.
    let mut hasher = Sha512::new();

    // Inputs the seed into the hash object.
    hasher.update(& seed);

    // Processes the seed and outputs the final hash in binary.
    let seed = hasher.finalize();

    // Encodes the binary hash as a Base94 String.
    let mut seed = encode(& seed, 94);

    seed.truncate(length.try_into().unwrap());

    // Returns the final Base94 String.
    seed
}

// Processes command line arguments and then outputs a Vec of Strings
// that can be much more easily parsed into variables.
fn process_args(args: Vec<String>) -> Vec<String> {

    // Vector that catches all the values processed here.
    let mut output = Vec::new();
    
    // Iterates through the arguments as input.
    for argument in args {
        match argument.as_str() {

            // Displays the help text.
            "help" => { help(); }

            // Sets the program to grab the next argument as password_length.
            "length" => { output[1] = String::from("0"); }

            // Catches errors and handles the value for password_length and program_name.
            _ => {

                // Grabs the program name and saves it.
                if output.is_empty() {
                    output.push(String::from(argument));

                    // Sets the default value for password_length.
                    output.push(String::from("32"));

                // Catches the value for password_length and handles errors.
                } else if *output.get(1).unwrap() == String::from("0") {
                    match argument.parse::<i32>() {

                        // When password_length value is valid it saves it for later.
                        Ok(n) => {
                            output[1] = n.to_string();
                        }

                        // When password_length value is invalid, it notifies the user and exits.
                        Err(e) => {
                            println!("{}. 'length' value is not a valid integer.", e);
                            process::exit(0);
                        }
                    }

                // Catches invalid arguments, notifies user and exits.
                } else {
                    println!("{} is not a valid argument.", argument);
                    process::exit(0);
                }
            }
        }
    }

    output
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
        let output = hash_and_base94(String::from("testing"), 1000);
        assert_eq!(output, comparitor);
    }
}

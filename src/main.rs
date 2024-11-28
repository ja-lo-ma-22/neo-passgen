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

    // Sends the command-line arguments to a function to process,
    // and returns an easy Vec<String> to parse.
    let args = process_args(args);

    // List of values from process_args() :
    // .0 = program_name
    // .1 = password_length
    // .2 = hashing count

    // Collects the String data from the user and processes potential errors.
    io::stdin()
        .read_line(&mut seed)
        .expect("Failed to read seed.");

    // Removes trailing '/n' newline character.
    seed.pop();

    // Calls the function and recieves a value.
    let seed = hash_base94(seed, args.1, args.2);
    
    // Prints the final seed to the command line for the user.
    println!("{}", seed);
}

// Accepts a seed and hashes it. Then outputs a String of the
// has in Base94.
fn hash_base94(seed: String, length: u32, count: u32) -> String {
    // Creates hash object to process the seed.
    let mut hasher = Sha512::new();

    // Inputs the seed into the hash object.
    for _n in 0..count {
        hasher.update(& seed);

        // Causes a change in length to change the hash entirely.
        hasher.update(length.to_string());
    }

    // Processes the seed and outputs the final hash in binary.
    let seed = hasher.finalize();

    // Encodes the binary hash as a Base94 String.
    let mut seed = encode(& seed, 94);

    seed.truncate(length as usize);

    // Returns the final Base94 String.
    seed
}

// Processes command line arguments and then outputs a tuple.
// that can be much more easily parsed into variables.
fn process_args(args: Vec<String>) -> (String, u32, u32) {

    // Tuple that catches all the values processed here.
    // Default password_length is defined as index 1.
    let mut output: (String, u32, u32) = (String::from("blank"), 32, 1);
    
    // Iterates through the arguments as input.
    for argument in args {
        match argument.as_str() {

            // Displays the help text.
            "help" => { help(); }

            // Sets the program to grab the next argument as password_length.
            "length" => { output.1 = 0; }

            "count" => { output.2 = 0; }

            // Catches errors and handles the value for password_length
            // and program_name.
            _ => {

                // Grabs the program name and saves it.
                if output.0 == String::from("blank") {
                    output.0 = String::from(argument);

                // Catches the value for password_length and handles errors.
                } else if output.1 == 0 {
                    match argument.parse::<u32>() {

                        // When password_length value is valid it saves it for later.
                        Ok(n) => {
                            output.1 = n;
                        }

                        // When password_length value is invalid,
                        // it notifies the user and exits.
                        Err(e) => {
                            println!("{}. 'length' value is not a valid integer.", e);
                            process::exit(0);
                        }
                    }

                // Catches the value for hashing count.
                } else if output.2 == 0 {
                    match argument.parse::<u32>() {
                        Ok(n) => {
                            output.2 = n;
                        }

                        Err(e) => {
                            println!("{}. 'count' value is not a valid integer.", e);
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
    fn hash_output() {

        // Correct output for hash.
        let comparitor = String::from("vHZ%T4#B(*vd.I}{J=pp`a:k)]8Y(HH?FZjX^(iyqh19!GL6r`>}q5cKXzu5?+1,K8~%q/DGK,(_xm");

        // Processed hash inputs for the correct output.
        let output = hash_base94(String::from("apple"), 1000, 1);

        // Tests that processed output and correct output are the same.
        assert_eq!(output, comparitor);
    }

    #[test]
    fn hash_default_length() {
        
        // Set of arguments processed.
        let output = hash_base94(String::from("hello"), 32, 1);

        // Correct output for comparison.
        let comparitor = String::from("msBE(8v`nsxt&u>0i|wzw_]ygwX0-mLG");

        // Tests that the length is correct.
        assert_eq!(output.len(), 32);

        // Tests that the output is correct.
        assert_eq!(comparitor, output);
    }

    #[test]
    fn hash_custom_length() {

        // Set of arguments processed.
        let output = hash_base94(String::from("peanut butter"), 20, 1);

        // Correct output
        let comparitor = String::from("xsO=>hRA`JzZ;!xEHA-w");

        assert_eq!(output.len(), 20);

        assert_eq!(output, comparitor);
    }

    #[test]
    fn hash_custom_count() {

        // Set of arguments processed.
        let output = hash_base94(
            String::from("banana"),
            32,
            6
        );

        // Correct output
        let comparitor = String::from("-0l:kt5AMKduvK=#):&^U,rN'{}[6-?t");

        // Incorrect output
        let bad_comparitor = String::from("*]-{g?k%$-fXc(|AmM5m%i6m3c8+}Jpcdjnf");

        // Tests for count of 1 instead.
        assert_ne!(output, bad_comparitor);
        
        // Tests for correct output.
        assert_eq!(output, comparitor);
    }

    #[test]
    fn hash_custom_length_count() {

        // Set of arguments processed.
        let output = hash_base94(
            String::from("foo"),
            55,
            8
        );

        // Correct output
        let comparitor = String::from(
            "-!Jvf.yn_#?Ko3LsZcq_;p,y33c)2yPv)1Ve6oh.h5hV'i5VV#Za;U2");

        // Incorrect output
        let bad_comparitor = String::from(
            ")NHu`+PqgbtUfn#7f7Ugia]'H]|ux{-M*wajer;EXg==I&R~^4U&&M$");

        // Tests for count of 1 instead.
        assert_ne!(output, bad_comparitor);

        // Tests for correct output.
        assert_eq!(output, comparitor);
    }

    #[test]
    fn hash_length_change() {

        // First set of arguments processed.
        let mut output_1 = hash_base94(
            String::from("carrot"),
            32,
            1
        );

        // Second set of arguments processed.
        let mut output_2 = hash_base94(
            String::from("carrot"),
            33,
            1
        );

        output_1.truncate(32);
        output_2.truncate(32);

        // Tests that they are not identical.
        assert_ne!(output_1, output_2);
    }

    #[test]
    fn process_no_args() {

        // Fake set of arguments.
        let args = vec![String::from("program/name")];

        // Porcesses fake arguments.
        let out_args = process_args(args);

        // Correct output.
        let comparitor: (String, u32, u32) = (String::from("program/name"), 32, 1);

        // Tests ouput against correct output.
        assert_eq!(out_args, comparitor);
    }

    #[test]
    fn process_length_args() {

        // Fake input arguments.
        let args = vec![
            String::from("folder/program/name"),
            String::from("length"),
            String::from("50")
        ];

        // Processes fake input args.
        let out_args = process_args(args);

        // Correct processed args.
        let comparitor: (String, u32, u32) = (
            String::from("folder/program/name"),
            50, 
            1
        );

        // Tests that the correct args and the processed args are equal.
        assert_eq!(comparitor, out_args);
    }

    #[test]
    fn process_count_args() {

        // Fake inpu arguments.
        let args = vec![
            String::from("folder/program"),
            String::from("count"),
            String::from("5")
        ];

        // Processes fake arguments.
        let out_args = process_args(args);

        // Correct output arguments.
        let comparitor: (String, u32, u32) = (
            String::from("folder/program"),
            32,
            5
        );

        // Tests that the processed args are correct.
        assert_eq!(comparitor, out_args);
    }

    #[test]
    fn process_length_count_args() {

        // Fake input arguments.
        let args = vec![
            String::from("folder/another/program/name"),
            String::from("length"),
            String::from("60"),
            String::from("count"),
            String::from("4")
        ];

        // Processes fake innput arguments.
        let out_args = process_args(args);

        // Correct output arguments.
        let comparitor: (String, u32, u32) = (
            String::from("folder/another/program/name"),
            60,
            4
        );

        // Tests that the correct args and the processed args are equal.
        assert_eq!(comparitor, out_args);
    }
}

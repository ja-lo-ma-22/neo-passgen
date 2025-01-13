// converts a seed string into a hashed password string in base94.
//
// summary:
// seed string -> sha512 -> base94 -> password
//
//
// O(n) notation:
//
// O(x * y) where:
//
// x is the length
// y is the hashes
//
//
// Improvements:
//
// * Replace all data types with a struct and impl
// * Implement multithreading for hash_base94()
// * Refactor and optimize process_args()
//
// * Fill in help()
// * Implement 'example' argument
// * Start documentation

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

    // collects command-line arguments into a vector
    let raw_args: Vec<String> = env::args().collect();

    // Sends the command-line arguments to a function to process,
    // and returns an easy Vec<String> to parse.
    let args = process_args(raw_args);

    // List of values from process_args() :
    // .0 = program name
    // .1 = seed
    // .2 = password length
    // .3 = hashing count
    // .4 = debug info

    // Calls the function and recieves a value.
    let password = hash_base94(args);
    
    // Prints the final seed to the command line for the user.
    println!("{}", password);
}





enum Hashing {
    Args(String, String, u32, u32, bool),
    Pass(String)
}

impl Hashing {

    fn new(input: Vec<String>) -> Self {
        // TODO
    }

    fn hash(Self) -> Self {
        // TODO
    }
}





// Accepts a seed and hashes it. Then outputs a String of the
// has in Base94.
fn hash_base94((_prog_name, seed, length, hashes, debug): (String, String, u32, u32, bool)) -> String {

    // Final String to output.
    let mut password = String::new();

    // How many chunks the seed String will be cut into.
    let chunk_count = ( length / 75 ) + 1;

    // Creates the number of chunks (of hashing objects) in the vector.
    for a in 0..chunk_count {

        // Creates a hashing object.
        let mut hasher = Sha512::new();

        // Sets the seed for the object.
        hasher.update(& seed);

        // Makes the seed unique.
        hasher.update(a.to_string());

        // Makes the password unique for different lengths.
        hasher.update(length.to_string());

        // Hashes the number of times as the count.
        for count in 0..hashes {
            hasher.update(count.to_string());
        }

        // Encodes the final hash as a base94 String.
        let mut carrier = encode(& hasher.finalize(), 94);

        // Sets the size of the String.
        carrier.truncate(75);

        // Puts the finished String onto the password.
        password.push_str(&carrier);
    }

    password.truncate(length as usize);

    if debug == true {
        println!("Password length is: {}", password.len());
    }

    // Returns the final Base94 String.
    password
}

// Processes command line arguments and then outputs a tuple
// that can be much more easily parsed into variables.
fn process_args(args: Vec<String>) -> (String, String, u32, u32, bool) {

    // Tuple that catches all the values processed here.
    // The program name is defined as index 0.
    // Seed String is defined as index 1.
    // Default password_length is defined as index 2.
    // Default hashing count is defined as index 3.
    // Default debug behavior is defined as index 4.
    let mut proc_args = (
        String::new(),
        String::new(),
        32,
        1,
        false);
    
    // Iterates through the arguments as input.
    for argument in args {
        match argument.as_str() {

            // Displays the help text.
            "help" => { help(); }

            // Sets the seed argument for benchmarking.
            "benchmark" => { proc_args.1 = String::from("benchmark"); }

            // Sets the program to grab the next argument as password_length.
            "length" => { proc_args.2 = 0; }

            // Accepts a value to change the count for hashing.
            "hashes" => { proc_args.3 = 0; }

            // Turns debug information on.
            "debug" => { proc_args.4 = true; }

            // Catches errors and handles the value for password_length
            // and program_name.
            _ => {

                // Grabs the program name and saves it.
                if proc_args.0.is_empty() {
                    proc_args.0 = String::from(argument);

                // Catches the value for password_length and handles errors.
                } else if proc_args.2 == 0 {
                    match argument.parse::<u32>() {

                        // When password_length value is valid it saves it for later.
                        Ok(n) => {
                            proc_args.2 = n;
                        }

                        // When password_length value is invalid,
                        // it notifies the user and exits.
                        Err(e) => {
                            println!("{}. 'length' value is not a valid integer.", e);
                            process::exit(0);
                        }
                    }

                // Catches the value for hashing count.
                } else if proc_args.3 == 0 {
                    match argument.parse::<u32>() {

                        // Sets the value for hashing count.
                        Ok(n) => {
                            proc_args.3 = n;
                        }

                        // Catches errors, notifies user and exits.
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

    if proc_args.1.is_empty() {

        let mut carrier = String::new();

        io::stdin()
            .read_line(&mut carrier)
            .expect("Failed to read line.");

        carrier.pop();

        proc_args.1 = carrier;
    }

    proc_args
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

        // Input tuple of arguments.
        let input = (
            String::from("program/name"),
            String::from("apple"),
            32,
            1,
            false
        );

        // Processed hash inputs for output.
        let output = hash_base94(input);

        // Correct output for hash.
        let comparitor = String::from("<#*6'Y:[tndK3%T`qtD$(C`eIS])]A6?");

        // Tests that processed output and correct output are the same.
        assert_eq!(output, comparitor);
    }

    #[test]
    fn hash_default_length() {

        // Input tuple of arguments.
        let input = (
            String::from("program/name"),
            String::from("hello"),
            32,
            1,
            false
        );
        
        // Set of arguments processed.
        let output = hash_base94(input);

        // Correct output for comparison.
        let comparitor = String::from("|#auduHx~Lm>V00&2Pu{O;]rd-QZT+|:");

        // Tests that the length is correct.
        assert_eq!(output.len(), 32);

        // Tests that the output is correct.
        assert_eq!(comparitor, output);
    }

    #[test]
    fn hash_custom_length() {
        
        // Input tuple of arguments.
        let input = (
            String::from("program/name"),
            String::from("peanut butter"),
            20,
            1,
            false
        );

        // Set of arguments processed.
        let output = hash_base94(input);

        // Correct output
        let comparitor = String::from("&%dWJ|:iD3q)'X'r(vOy");

        assert_eq!(output.len(), 20);

        assert_eq!(output, comparitor);
    }

    #[test]
    fn hash_custom_count() {

        // Set of arguments processed.
        let input = (
            String::from("program/name"),
            String::from("banana"),
            32,
            6,
            false
        );

        // Processed input arguments.
        let output = hash_base94(input);

        // Correct output
        let comparitor = String::from(r"Q1!0.cxUpSJcc@m4y-PEX~O=nRZ0_5{3");

        // Incorrect output
        let bad_comparitor = String::from(r"nTX$_F\o>hv8HxHXMU#~vm|vp|Up>7kC");

        // Tests for count of 1 instead.
        assert_ne!(output, bad_comparitor);
        
        // Tests for correct output.
        assert_eq!(output, comparitor);
    }

    #[test]
    fn hash_custom_length_count() {

        // Set of arguments processed.
        let input = (
            String::from("program/name"),
            String::from("foo"),
            55,
            8,
            false
        );

        // Output arguments.
        let output = hash_base94(input);

        // Correct output
        let comparitor = String::from(
            "4i`M~Mf9r7Tk`]N;q6t'lpuN(/~qFC?V9u5&=tMO}4#m!$gBcBZqr<a");

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
        let input_1 = (
            String::from("program/name"),
            String::from("carrot"),
            32,
            1,
            false
        );

        let mut output_1 = hash_base94(input_1);

        // Second set of arguments processed.
        let input_2 = (
            String::from("program_name"),
            String::from("carrot"),
            33,
            1,
            false
        );

        let mut output_2 = hash_base94(input_2);

        output_1.truncate(32);
        output_2.truncate(32);

        // Tests that they are not identical.
        assert_ne!(output_1, output_2);
    }

    #[test]
    fn hash_length_longer() {
        
        // Set of input arguments.
        let input = (
            String::from("program_name"),
            String::from("hello"),
            500,
            1,
            false
        );

        let output = hash_base94(input);

        assert_eq!(output.len(), 500);
    }

    #[test]
    fn process_no_args() {

        // Fake set of arguments.
        let args = vec![
            String::from("program/name"),
            String::from("benchmark")
        ];

        // Porcesses fake arguments.
        let out_args = process_args(args);

        // Correct output.
        let comparitor: (String, String, u32, u32, bool) = (
            String::from("program/name"),
            String::from("benchmark"),
            32,
            1,
            false);

        // Tests ouput against correct output.
        assert_eq!(out_args, comparitor);
    }

    #[test]
    fn process_length_args() {

        // Fake input arguments.
        let args = vec![
            String::from("folder/program/name"),
            String::from("length"),
            String::from("50"),
            String::from("benchmark")
        ];

        // Processes fake input args.
        let out_args = process_args(args);

        // Correct processed args.
        let comparitor: (String, String, u32, u32, bool) = (
            String::from("folder/program/name"),
            String::from("benchmark"),
            50, 
            1,
            false
        );

        // Tests that the correct args and the processed args are equal.
        assert_eq!(comparitor, out_args);
    }



    // WARNING::
    //
    // This test right here caused me a LOT of headache.
    //
    // I could not for the life of me figure out why it wouldn't
    // run... Turns out that I used the wrong argument down there:

    #[test]
    fn process_count_args() {

        // Fake input arguments.
        let args = vec![
            String::from("folder/program"),

            // This was 'count' when it was broken.
            String::from("hashes"),
            String::from("5"),
            String::from("benchmark")
        ];

        // Processes fake arguments.
        let out_args = process_args(args);

        // Correct output arguments.
        let comparitor: (String, String, u32, u32, bool) = (
            String::from("folder/program"),
            String::from("benchmark"),
            32,
            5,
            false
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
            String::from("hashes"),
            String::from("4"),
            String::from("benchmark")
        ];

        // Processes fake innput arguments.
        let out_args = process_args(args);

        // Correct output arguments.
        let comparitor: (String, String, u32, u32, bool) = (
            String::from("folder/another/program/name"),
            String::from("benchmark"),
            60,
            4,
            false
        );

        // Tests that the correct args and the processed args are equal.
        assert_eq!(comparitor, out_args);
    }
}

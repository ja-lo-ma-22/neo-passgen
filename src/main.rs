use neo_passgen::hashing_arguments;

//use neo_passgen::hashing_arguments::HashArguments;

use std::env;

fn main() {

    println!("Starting in main()...");

    // Collects command-line arguments
    let args: Vec<String> = env::args().collect();

    println!("Collected arguments.");
    
    // Pulls variables out to use them in the program.
    let seed = args[1].clone();
    let hashcount = args[2].parse::<u64>().expect("hashcount");
    let length = args[3].parse::<u64>().expect("length");
    let threads = args[4].parse::<u64>().expect("threads");

    println!("Distributed arguments.");
    
    // Uses the autohash() function.
    println!("Hashing in main()...");
    let printme = hashing_arguments::autohash(seed, hashcount, length, threads);

    println!("Done hashing in main().");
    println!("Your hash is:\n\n{}\n", printme);
}

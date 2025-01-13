// A public module for turning Strings into hashed Strings.
pub mod hashing_arguments {

    // SHA512 hashes binary data
    use sha2::{Sha512, Digest};

    // Base94 converts data to base94 String
    use base94::encode;

    // For multithreading.
    use std::sync::mpsc;
    use std::thread;

    // Automatically runs the backend for you.
    pub fn autohash(
        seed: String,
        hashcount: u64,
        length: u64,
        threads: u64) -> String {

        println!("Starting autohash()...");
    
        let mut autotype = HashArguments::new(seed, hashcount, length, threads);

        println!("Finished building HashArguments type.");

        if autotype.threads == 1 {

            println!("Hashing singlethreaded...");

            // Single threaded hashing.
            autotype.hash();

            println!("Done.");

        } else {

            println!("Hashing multithreaded...");
            
            // Multithreaded hashing.
            autotype.hash_multi();

            println!("Done.");
        }

        println!("Encoding...");

        autotype.encode();

        println!("Done");

        println!("Finishing...");

        autotype.finish()
    }

    // Creates a type for use in multithreading
    #[derive(Clone, Debug)]
    struct SeedType {
        chunks: Vec<String>,
        index: u64,
        hashes: u64,
        num: u64
    }

    impl SeedType {

        fn new(chunk: String, index: u64, hashes: u64, num: u64) -> Self {

            // Creates an empty vector.
            let mut vectorstring = Vec::new();

            // Adds the string as the first part of the vector.
            vectorstring.push(chunk);

            // Creates the type.
            Self {
                chunks: vectorstring,
                index,
                hashes,
                num
            }
        }

        fn set_index(&mut self, input: u64) {
            
            // Sets the index value.
            self.index = input;
        }

        fn set_num(&mut self, input: u64) {
            
            // Sets the num value.
            self.num = input;
        }
        
        fn hash_chunk(&mut self){ 

            // Creates a set of seeds.
            for a in 1..self.num {
                self.chunks.push(self.chunks[0].clone() + &( self.index + a ).to_string());
            }

            // Concatenates the index.
            self.chunks[0] = self.chunks[0].clone() + &self.index.to_string();

            // Hashes the input multiple times
            for ref mut b in self.chunks.clone() {
                   
                // Creates hasher object.
                let mut hasher = Sha512::new();

                // Hashes the input multiple times
                for _d in 0..self.hashes {
                    hasher.update(&b);
                }

                // Returns the finished seed
                *b = format!("{:X}", hasher.finalize());
            }

        }

        fn finish(self) -> String {
            let mut output = String::new();
            for chunk in self.chunks {
                output = output + &chunk;
            }
            output
        }
    }

    // The public type that is used to hash Strings.
    pub struct HashArguments {
        seed: String,
        hashcount: u64,
        length: u64,
        threads: u64
    }

    impl HashArguments {
        
        // A simple constructor function for the type.
        pub fn new(
            seed: String, 
            hashcount: u64,
            length: u64,
            threads: u64
            ) -> Self {
            
            Self {
                seed,
                hashcount,
                length,
                threads,
            }

        }

        // Hashes the type. This version runs in a single thread.
        pub fn hash(&mut self) {

            // Sanity check for the inputs.
            if self.threads == 0 {
                panic!("A thread count of 0 is impossible.");
            } else if self.threads != 1 {
                panic!("This method is for single threaded hashing only.");
            }

            let chunk_count: u64;

            // Calculates the number of chunks needed.
            if ( self.length % 35 ) != 0 {
                chunk_count = ( self.length / 35 ) + 1;
            } else {
                chunk_count = self.length / 35;
            } 

            // A basic chunk of seed for the hasher.
            let seed_chunk = self.seed.clone() + &self.length.to_string();

            // Clears the seed String.
            self.seed.clear();

            // Hashes clones of the seed_chunk into the String.
            for index in 0..chunk_count {
                self.seed.push_str(&Self::hash_chunk(seed_chunk.clone(), self.hashcount, index));
            }
        }

         // Hashes the type. This version is multithreaded.
        pub fn hash_multi(&mut self) {

            println!("Starting hash_multi()...");

            // Sanity check for the inputs.
            if self.threads == 0 {
                panic!("A thread count of 0 is impossible.");
            } else if self.threads == 1 {
                panic!("This method is for multithreaded hashing only.");
            }

            println!("Checked thread count.");

            let chunk_count: u64;

            // Calculates the number of chunks needed.
            if ( self.length % 35 ) != 0 {
                chunk_count = ( self.length / 35 ) + 1;
            } else {
                chunk_count = self.length / 35;
            }

            println!("Calculated chunk count: {}", chunk_count);

            if self.threads > chunk_count {
                self.threads = chunk_count;
                println!("Reduced thread count due to length being short.");
            }

            println!("Checked thread count again.");

            println!("Thread count: {}", self.threads);

            // Calculates chunk count per thread.
            let thread_chunk_count: u64 = chunk_count / self.threads;

            println!("thread_chunk_count: {}", thread_chunk_count);

            let thread_remainder_count: u64 = chunk_count % self.threads;

            println!("thread_remainder_count: {}", thread_remainder_count);

            // Creates a seed_type.
            let seed = SeedType::new(
                self.seed.clone() + &self.length.to_string(),
                0,
                self.hashcount,
                0
                );

            println!("Created seed type.");

            // Clears the seed String.
            self.seed.clear();

            // MULTITHREADING
            // Creates a transmitter to receive types.
            let (tx, rx) = mpsc::channel();

            // Catches all thread handles.
            let mut handles = Vec::new();

            // Catches the finished chunks.
            let mut chunks_done = Vec::new();

            println!("Setting up threads...");

            // Creates chunks of seed_type and pushes them to a thread.
            for a in 1..self.threads {

                // Creates clone of SeedType.
                let mut chunk = seed.clone();

                // Sets the index and num.
                chunk.set_index(a * thread_chunk_count);
                chunk.set_num(thread_chunk_count);

                // Clones the transmitter.
                let transmit = tx.clone();

                // Copied index.
                let b = a;

                println!("Set up thread #{}", a);

                // Creates a handle and starts a thread.
                let handle = thread::spawn(move || {
                    println!("Starting thread #{}", b);
                    chunk.hash_chunk();
                    transmit.send(chunk).unwrap();
                    println!("Finished thread #{}", b);
                });

                // Catches the handles.
                handles.push(handle);
            }

            std::mem::drop(tx);

            println!("Caught thread handles");

            println!("Allocating space...");

            // Allocates space for chunks.
            for _b in 0..self.threads {
                chunks_done.push(seed.clone());
            }

            println!("Catching chunks...");

            // Catches all finished threads.
            for recieved in rx {
                println!("rx got: {:?}", recieved);
                let index = recieved.index / thread_chunk_count;
                chunks_done[index as usize] = recieved;
                println!("rx Done.");
            }

            println!("Shutting down threads...");

            // Closes all threads.
            for c in handles {
                c.join().unwrap();
            }

            println!("Combining chunks...");

            // Hashes clones of the seed_chunk into the String.
            for seed in chunks_done {
                self.seed.push_str(&seed.finish());
            }
            
            println!("Done.");
        }

        // TODO!
        // Accepts a chunk of the seed and hashes it.
        fn hash_chunk(mut seed_chunk: String, hashes: u64, index: u64) -> String {

            // Creates hasher object.
            let mut hasher = Sha512::new();

            // Concatenates the index.
            seed_chunk = seed_chunk + &index.to_string();

            // Hashes the input multiple times
            for _i in 0..hashes {
                hasher.update(&seed_chunk);
            }

            // Returns the finished seed
            format!("{:X}", hasher.finalize())
        }

        // TODO!
        // Hashes the type. This version is multithreaded.
        //pub fn _hash_multi(&mut self) {
        //
        //}

        // Encodes the String in base94.
        pub fn encode(&mut self) {
            
            // Encodes the String.
            self.seed = encode(&self.seed.clone().into_bytes(), 94);

            // Shortens the String to the proper length.
            self.seed.truncate(self.length as usize);
        }

        // Destructor function. Encodes and returns just the String.
        pub fn finish(self) -> String {

            // Returns just the seed.
            self.seed
        }
    } 
}

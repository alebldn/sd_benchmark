#### SD Benchmark 
This rust library provides means to benchmark different selective disclosure mechanisms.

The key performance metrics included in the benchmark against the amount of claims included in the Verifiable Credential are:

-  Verifiable Credential length.
-  Verifiable Credential generation latency.
-  Verifiable Credential verification latency.

Conversely, the key performance metrics included in the benchmark against the amount of **disclosed** claims included in the Verifiable Presentation:

-  Verifiable Presentation length.
-  Verifiable Presentation generation latency.
-  Verifiable Presentation verification latency.

Finally, the library provides benchmarks concerning the asymmetric mechanisms employed in providing selective disclosure using the following performance metrics:

- Key size. 
- Key generation latency.

To run all the available tests in the library, execute in the project directory `cargo test`.
To run the benchmark, execute in the project directory `cargo run -r`.

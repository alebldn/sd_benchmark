#### SD Benchmark 
This rust library provides means to benchmark different selective disclosure mechanisms.

The key performance metrics included in the benchmark against the amount of claims included in the Verifiable Credential
are:

-  Verifiable Credential length.
-  Verifiable Credential generation latency.
-  Verifiable Credential verification latency.

Conversely, the key performance metrics included in the benchmark against the amount of **disclosed** claims included in
the Verifiable Presentation:

-  Verifiable Presentation length.
-  Verifiable Presentation generation latency.
-  Verifiable Presentation verification latency.

Finally, the library provides benchmarks concerning the asymmetric mechanisms employed in providing selective disclosure
using the following performance metrics:

- Key size. 
- Key generation latency.

To run all the available tests in the library, execute in the project directory `cargo test`.
To run the benchmark, execute in the project directory `cargo run -r`.

External libraries: 

- [Openssl](https://openssl-library.org/) 
- [GMP](https://gmplib.org/). Automatically included in the software. Requires UNIX-like os and a working C compiler to 
build it from scratch (documentation is available [here](https://docs.rs/gmp-mpfr-sys/latest/gmp_mpfr_sys/index.html#building-on-gnulinux)). The dependency, required to benchmark the CL signature 
scheme, can be disabled by removing "cl03" from default features in **Cargo.toml**.

Troubleshooting:
Depending on the OS and internal linking, the automatic compilation of "gmp-fmr-sys" might fail to find a suitable C 
compiler. After making sure that the compiler is installed, it is generally possible to solve the issue by specifying 
the compiler via an environment variable before calling the rust compiler, as shown below:
- `CC=clang cargo build -r`
- `CC=clang cargo run -r`

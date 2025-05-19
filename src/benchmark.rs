use std::time::{Duration, Instant};
use crate::adapters::adapter::Adapter;

/// An empty struct whose methods permit to retrieve the duration execution of a given function.
pub struct Benchmark {}

impl Benchmark {

    /// Benchmarks a function by executing it several times and averaging the results
    ///
    /// # Arguments
    /// * `func` - Function to be executed.
    /// * `iterations` - Amount of times that the function needs to be executed for average.
    ///
    /// # Returns
    /// A result containing either the averaged duration or a string containing an error.
    ///
    /// # Example
    /// ```
    /// use sd_benchmark::benchmark::Benchmark;
    /// fn print_example() -> Result<(), String> { println!("Example"); Ok(())}
    /// let result = Benchmark::benchmark_function(print_example, 100);
    /// ```
    pub fn benchmark_function<F, T>(func: F, iterations: i8) -> Result<(Duration, T), String>
    where
        F: Fn() -> Result<T, String>
    {
        let mut start: Instant;
        let mut result = None;
        let mut total: f64 = 0f64;

        for _ in 0..iterations {
            start = Instant::now();
            match func() {
                Ok(inner) => { result = Some(inner) }
                Err(err) => { println!("Benchmarked function returned error [{err}]") }
            }

            total = total + start.elapsed().as_secs_f64();
        }

        let average_duration: Duration = Duration::from_secs_f64(total / (iterations as f64));
        match result {
            Some(result) => { Ok((average_duration, result)) },
            None => { Err("Function did not return a result".to_string()) }
        }
    }


    /// Benchmarks an adapter initialization function. This is needed because when creating instances nested inside adapters, they're of type "dyn Adapter".
    ///
    /// # Arguments
    /// * `func` - Function to be executed.
    /// * `iterations` - Amount of times that the function needs to be executed for average.
    ///
    /// # Returns
    /// A result containing either the averaged duration or a string containing an error.
    pub fn benchmark_initialization<F, T>(func: F, iterations: i8) -> Result<(Duration, Box<T>), String>
    where
        F: Fn() -> Result<T, String>,
        T: Adapter,
    {
        let (duration, result) = Benchmark::benchmark_function(func, iterations)?;
        Ok((duration, Box::new(result)))
    }
}
use criterion::{criterion_group, criterion_main, Criterion};
use bloomfilter::Bloom;
use cdk::nuts::PublicKey;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Instant;

fn bench_bloom_filter(c: &mut Criterion) {
    let num_items = 100000;
    let fp_rate = 0.001;
    let bloom = Arc::new(Mutex::new(Bloom::new_for_fp_rate(num_items, fp_rate).unwrap()));

    c.bench_function("bloom_filter_queries", |b| {
        b.iter(|| {
            let bloom_clone = bloom.clone();
            let keys: Vec<PublicKey> = vec![]; // Populate with test keys

            let start = Instant::now();
            let handles: Vec<_> = (0..10).map(|_| {
                let bloom_clone = bloom_clone.clone();
                let keys = keys.clone();
                thread::spawn(move || {
                    let bloom = bloom_clone.lock().unwrap();
                    for key in keys.iter() {
                        bloom.check(key);
                    }
                })
            }).collect();

            for handle in handles {
                handle.join().unwrap();
            }
            let duration = start.elapsed();
            println!("Time elapsed in bloom filter query is: {:?}", duration);
        });
    });
}

criterion_group!(benches, bench_bloom_filter);
criterion_main!(benches);

use criterion::{criterion_group, criterion_main, Criterion};
use bloomfilter::Bloom;
use cdk::nuts::{SecretKey, PublicKey};
use std::sync::{Arc, Mutex};
use std::thread;
use rand::{rng, RngCore};

fn bench_bloom_filter(c: &mut Criterion) {
    let num_items = 100;
    let fp_rate = 0.001;
    let bloom: Arc<Mutex<Bloom<PublicKey>>> = Arc::new(Mutex::new(Bloom::new_for_fp_rate(num_items, fp_rate).unwrap()));
    let mut rng = rng();
    let keys: Vec<PublicKey> = (0..num_items).map(|_| {
        let mut random_bytes: [u8; 32] = [0u8; 32];
        rng.fill_bytes(&mut random_bytes);
        SecretKey::from_slice(&random_bytes).expect("valid secret key bytes").public_key()
    }).collect();

    c.bench_function("bloom_filter_queries", |b| {
        b.iter(|| {
            let handles: Vec<_> = (0..10).map(|_| {
                let keys = keys.clone();
                let bloom_cloned = bloom.clone();
                thread::spawn(move || {
                    {
                        let bloom_locked = bloom_cloned.lock().unwrap();
                        for k in keys.iter() {
                            let _ = bloom_locked.check(k);
                        }
                    }
                })
            }).collect();

            for handle in handles {
                handle.join().unwrap();
            }
        });
    });
}

criterion_group!(benches, bench_bloom_filter);
criterion_main!(benches);

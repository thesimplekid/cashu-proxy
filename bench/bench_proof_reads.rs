use criterion::{criterion_group, criterion_main, Criterion};
use std::sync::Arc;
use tokio::runtime::Runtime;
use std::thread;
use std::time::Instant;
use src::db::{Db, ProofWithKey};
use cdk::nuts::PublicKey;

fn bench_proof_reads(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    let db_path = PathBuf::from("path/to/db");
    let db = Arc::new(Db::new(&db_path).unwrap());

    c.bench_function("read_proofs", |b| {
        b.iter(|| {
            let db_clone = db.clone();
            let keys: Vec<PublicKey> = vec![]; // Populate with test keys

            let start = Instant::now();
            let handles: Vec<_> = (0..10).map(|_| {
                let db_clone = db_clone.clone();
                let keys = keys.clone();
                thread::spawn(move || {
                    rt.block_on(async {
                        db_clone.get_proofs_by_ys(&keys).unwrap();
                    });
                })
            }).collect();

            for handle in handles {
                handle.join().unwrap();
            }
            let duration = start.elapsed();
            println!("Time elapsed in proof read is: {:?}", duration);
        });
    });
}

criterion_group!(benches, bench_proof_reads);
criterion_main!(benches);

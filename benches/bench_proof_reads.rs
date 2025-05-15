use criterion::{criterion_group, criterion_main, Criterion};
use rand::{rng, RngCore};
use std::{path::PathBuf, sync::Arc};
use tokio::runtime::Runtime;
use std::thread;
use cashu_proxy::db::Db;
use cdk::nuts::PublicKey;
use cdk::nuts::SecretKey;

fn bench_proof_reads(c: &mut Criterion) {
    let num_items = 100;
    let db_path = PathBuf::from("test_data/database.redb");
    let db = Arc::new(Db::new(&db_path).unwrap());
    let mut rng = rng();
    let keys: Vec<PublicKey> = (0..num_items).map(|_| {
        let mut random_bytes: [u8; 32] = [0u8; 32];
        rng.fill_bytes(&mut random_bytes);
        SecretKey::from_slice(&random_bytes).expect("valid scalar bytes").public_key()
    }).collect();

    c.bench_function("read_proofs", |b| {
        b.iter(|| {
            let db_clone = db.clone();
            let handles: Vec<_> = (0..10).map(|_| {
                let db_clone = db_clone.clone();
                let keys = keys.clone();
                thread::spawn(move || {
                    let rt = Runtime::new().unwrap();
                    rt.block_on(async {
                        db_clone.get_proofs_by_ys(&keys).unwrap();
                    });
                })
            }).collect();

            for handle in handles {
                handle.join().unwrap();
            }
        });
    });
}

criterion_group!(benches, bench_proof_reads);
criterion_main!(benches);

thread_local! {
  pub static CPU_TP: rayon::ThreadPool = rayon::ThreadPoolBuilder::new()
      .thread_name(|i| format!("cpu-tp-{}", i))
      .num_threads(1).build().unwrap();
  pub static DNS_TP: rayon::ThreadPool = rayon::ThreadPoolBuilder::new()
      .thread_name(|i| format!("dns-tp-{}", i))
      .num_threads(4).build().unwrap();
}

use anyhow::Context;
use aya::{
    maps::perf::AsyncPerfEventArray,
    programs::{Xdp, XdpFlags},
    util::online_cpus,
    Bpf,
    maps::HashMap,
};
use bytes::BytesMut;
use std::{
    env, fs, net,
};
use tokio::{signal, task};

use k8s_network_policy_ebpf_controller_common::PacketLog;

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let path = match env::args().nth(1) {
        Some(path) => path,
        None => panic!("no path provided"),
    };
    let iface = match env::args().nth(2) {
        Some(iface) => iface,
        None => "eth0".to_string(),
    };

    let data = fs::read(path)?;
    let mut bpf = Bpf::load(&data)?;

    let program: &mut Xdp = bpf.program_mut("k8s_network_policy_ebpf_controller").unwrap().try_into()?;
    program.load()?;
    program.attach(&iface, XdpFlags::default())
        .context("failed to attach the XDP program with default flags - try changing XdpFlags::default() to XdpFlags::SKB_MODE")?;

    let mut blocklist: HashMap<_, u32, u32> = HashMap::try_from(bpf.map_mut("BLOCKLIST")?)?;
    let block_addr : u32 = net::Ipv4Addr::new(10, 8, 125, 12).try_into()?;
    blocklist.insert(block_addr, 0, 0)?;

    let mut perf_array = AsyncPerfEventArray::try_from(bpf.map_mut("EVENTS")?)?;
    
    for cpu_id in online_cpus()? {
        let mut buf = perf_array.open(cpu_id, None)?;

        task::spawn(async move {
            let mut buffers = (0..10)
                .map(|_| BytesMut::with_capacity(1024))
                .collect::<Vec<_>>();

            loop {
                let events = buf.read_events(&mut buffers).await.unwrap();
                for i in 0..events.read {
                    let buf = &mut buffers[i];
                    let ptr = buf.as_ptr() as *const PacketLog;
                    let data = unsafe { ptr.read_unaligned() };
                    let src_addr = net::Ipv4Addr::from(data.ipv4_address);
                    println!("LOG: SRC {}, SRCRAW {}, ACTION {}", src_addr, data.ipv4_address, data.action);
                }
            }
        });
    }
    
    signal::ctrl_c().await.expect("failed to listen for event");
    Ok::<_, anyhow::Error>(())
}
    

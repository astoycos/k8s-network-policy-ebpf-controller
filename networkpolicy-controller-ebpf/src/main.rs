#![no_std]
#![no_main]

use aya_bpf::{
    bindings::xdp_action,
    macros::{map, xdp},
    maps::PerfEventArray,
    programs::XdpContext,
    maps::HashMap,
};

use core::mem;
use memoffset::offset_of;
use networkpolicy_controller_common::PacketLog;

mod bindings;
use bindings::{ethhdr, iphdr};

#[map(name = "EVENTS")]
static mut EVENTS: PerfEventArray<PacketLog> = PerfEventArray::<PacketLog>::with_max_entries(1024, 0);

#[map(name = "BLOCKLIST")]
static mut BLOCKLIST: HashMap<u32, u32> = HashMap::<u32, u32>::with_max_entries(1024, 0);

#[xdp(name="k8s_network_policy_ebpf_controller")]
pub fn k8s_network_policy_ebpf_controller(ctx: XdpContext) -> u32 {
     match unsafe { try_k8s_network_policy_ebpf_controller(ctx) } {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

#[inline(always)]
unsafe fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*const T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();

    if start + offset + len > end {
        return Err(());
    }

    Ok((start + offset) as *const T)
}

fn block_ip(address: u32) -> bool {
    unsafe { BLOCKLIST.get(&address).is_some() }
}

unsafe fn try_k8s_network_policy_ebpf_controller(ctx: XdpContext) -> Result<u32, ()> {
    let h_proto = u16::from_be(unsafe { *ptr_at(&ctx, offset_of!(ethhdr, h_proto))? });
    if h_proto != ETH_P_IP {
        return Ok(xdp_action::XDP_PASS);
    }
    let source = u32::from_be(unsafe { *ptr_at(&ctx, ETH_HDR_LEN + offset_of!(iphdr, saddr))? });

    let action = if block_ip(source) {
        xdp_action::XDP_DROP
    } else {
        xdp_action::XDP_PASS
    };

    let log_entry = PacketLog {
        ipv4_address: source,
        action: action,
    };

    if source == 168328460 {
        unsafe {
            EVENTS.output(&ctx, &log_entry, 0);
        }
    }
    Ok(action)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}

const ETH_P_IP: u16 = 0x0800;
const ETH_HDR_LEN: usize = mem::size_of::<ethhdr>();

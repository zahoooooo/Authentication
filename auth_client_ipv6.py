import ctypes
import os
import struct
import socket
import time
import threading
import json
import argparse
import sys
import queue

# 1. 加载动态链接库
lib_path = os.path.abspath("./libauth.so")
libauth = ctypes.CDLL(lib_path)

# 定义接口类型
libauth.auth_init.restype = ctypes.c_int

libauth.auth_generate_packet.restype = ctypes.c_int
libauth.auth_generate_packet.argtypes = [
    ctypes.POINTER(ctypes.c_int * 3),    # int ids[3]
    ctypes.POINTER(ctypes.c_uint8),      # const uint8_t* plaintext (用指针避免\0截断)
    ctypes.POINTER(ctypes.c_char),       # char* out_data (可写缓冲区)
]

libauth.auth_parse_re_auth_signal.restype = ctypes.c_int
libauth.auth_parse_re_auth_signal.argtypes = [
    ctypes.c_char_p,
    ctypes.POINTER(ctypes.c_int * 3)
]

libauth.auth_select_algs_from_pool.restype = ctypes.c_int
libauth.auth_select_algs_from_pool.argtypes = [
    ctypes.c_char_p,
    ctypes.POINTER(ctypes.c_int * 3)
]

libauth.auth_set_timestamp.argtypes = [ctypes.c_uint64]

# 前端/上层系统可直接读取 9 个算法客观参数 JSON
libauth.auth_get_algorithm_security_json.restype = ctypes.c_char_p
libauth.auth_get_last_crypto_trace_json.restype = ctypes.c_char_p


def get_algorithm_security_infos():
    raw = libauth.auth_get_algorithm_security_json()
    if not raw:
        return []
    return json.loads(raw.decode('utf-8'))


# 可作为前端状态变量直接暴露：list[dict]，字段为 alg_id/name/family/key_bits/nonce_bits/tag_bits
algorithm_security_infos = get_algorithm_security_infos()

libauth.auth_init()

# --- 协议常量 ---
AUTH_NEXT_HEADER = 200       # 自定义认证协议号，收发两端保持一致
AUTH_PAYLOAD_LEN = 292       # 并行 AuthPacket: 4(policy_id) + 3*64(ciphertexts) + 3*32(tags)
SIGNAL_UDP_PORT = 19999     # UDP 备选信号通道端口

# --- 全局状态 ---
my_pool = "11,12,13,21,22,23,31,32,33"
DEFAULT_ALGS = [12, 22, 32]  # 正常模式：三组 192 位算法
SECURE_ALGS = [13, 23, 33]   # 攻击模式：三组 256 位算法
FAST_ALGS = [11, 21, 31]     # 高负载模式：三组 128 位算法
ALL_ALGS = set([11, 12, 13, 21, 22, 23, 31, 32, 33])
current_ids = DEFAULT_ALGS[:]
running = True
re_auth_event = threading.Event()
ids_lock = threading.Lock()
last_sent_payload = None
last_sent_payload_lock = threading.Lock()
lib_lock = threading.Lock()

# --- 发送统计 ---
stats_lock = threading.Lock()
stats_sent_ok = 0
stats_send_fail = 0
stats_gen_fail = 0
stats_generated = 0

# 默认不打印每包 trace，避免影响命令行输入；需要时用 --trace 或 AUTH_TRACE=1 打开
TRACE_ENABLED = os.environ.get("AUTH_TRACE", "0") != "0"

# --- 动态速率控制 ---
rate_lock = threading.Lock()
rate_update_event = threading.Event()
current_pps = 1.0
previous_positive_pps = 1.0
rate_generation = 0


def print_crypto_trace(prefix="Crypto Trace"):
    if not TRACE_ENABLED:
        return
    raw = libauth.auth_get_last_crypto_trace_json()
    if not raw:
        return
    try:
        info = json.loads(raw.decode('utf-8'))
    except Exception:
        print("\n[{}] {}".format(prefix, raw.decode('utf-8', 'ignore')))
        return
    steps = info.get("steps", [])
    print("\n[{}] operation={} step_count={}".format(prefix, info.get('operation'), info.get('step_count')))
    for step in steps:
        in_hex = step.get("input_hex", "")[:32]
        out_hex = step.get("output_hex", "")[:32]
        tag_hex = step.get("tag_hex", "")[:32]
        worker_thread_hash = step.get("worker_thread_hash", "")
        print("  L{} {} {} {} thread={} in={}... out={}... tag={}...".format(
            step.get('logical_layer'),
            step.get('algorithm_name'),
            step.get('direction'),
            step.get('status'),
            worker_thread_hash,
            in_hex,
            out_hex,
            tag_hex))


def set_current_pps(new_pps, source="stdin"):
    """Dynamically set the runtime send rate. new_pps <= 0 pauses sending."""
    global current_pps, previous_positive_pps, rate_generation
    try:
        new_pps = float(new_pps)
    except Exception:
        print("\n[Rate] invalid rate: {}".format(new_pps))
        return False
    if new_pps < 0:
        print("\n[Rate] rate must not be less than 0")
        return False

    with rate_lock:
        current_pps = new_pps
        if new_pps > 0:
            previous_positive_pps = new_pps
        rate_generation += 1
        gen = rate_generation
    rate_update_event.set()

    if new_pps > 0:
        print("\n[Rate] {} set send rate to {:.3f} pps".format(source, new_pps))
    else:
        print("\n[Rate] {} paused sending; enter resume or a new positive rate to resume".format(source))
    return True


def get_rate_state():
    with rate_lock:
        return current_pps, rate_generation


def handle_signal(signal_str):
    """Handle re-auth signals. This function only switches algorithms, not send rate."""
    global current_ids
    forced_ids = (ctypes.c_int * 3)()
    action = libauth.auth_parse_re_auth_signal(signal_str.encode('utf-8'), ctypes.byref(forced_ids))
    if action == 1:
        with ids_lock:
            current_ids = list(forced_ids)
        print("\n[Signal] switch algorithms -> {}".format(current_ids))
        re_auth_event.set()
    elif action == 2:
        # 兼容旧格式 CMD_RETRY_CONFIG_MISMATCH：没有携带服务端建议算法时，
        # 按本地算法池选择一组算法重试。正式对接建议服务端发送
        # CMD_RETRY_CONFIG_MISMATCH:x,y,z，由 action == 1 分支精确切换。
        retry_ids = select_random_algs(my_pool)
        with ids_lock:
            current_ids = retry_ids
        print("\n[Signal] retry mismatch -> select algorithms from local pool {}".format(current_ids))
        re_auth_event.set()


def select_random_algs(pool_str):
    c_ids = (ctypes.c_int * 3)()
    ret = libauth.auth_select_algs_from_pool(pool_str.encode('utf-8'), ctypes.byref(c_ids))
    if ret == 0:
        return list(c_ids)
    return [11, 12, 13]


def is_full_algorithm_pool(pool_str):
    try:
        values = set()
        for item in pool_str.split(','):
            item = item.strip()
            if item:
                values.add(int(item))
        return ALL_ALGS.issubset(values)
    except Exception:
        return False


def ipv6_addr_to_bytes(addr):
    return socket.inet_pton(socket.AF_INET6, addr)


def save_pcap(filename, packet_data):
    pcap_header = struct.pack("<I H H i I I I", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 101)
    now = time.time()
    sec, usec = int(now), int((now - int(now)) * 1000000)
    pkt_header = struct.pack("<I I I I", sec, usec, len(packet_data), len(packet_data))
    with open(filename, "wb") as f:
        f.write(pcap_header)
        f.write(pkt_header)
        f.write(packet_data)


def open_send_socket(ifname=None):
    sock = socket.socket(socket.AF_INET6, socket.SOCK_RAW, socket.IPPROTO_RAW)
    if ifname:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, ifname.encode('utf-8'))
    return sock


def send_packet(dst_ip, packet_data, sock=None, quiet=False):
    global last_sent_payload
    own_sock = False
    try:
        if sock is None:
            sock = open_send_socket()
            own_sock = True
        sock.sendto(packet_data, (dst_ip, 0, 0, 0))
        with last_sent_payload_lock:
            last_sent_payload = packet_data[40:] if len(packet_data) > 40 else None
        return True
    except Exception as e:
        if not quiet:
            print("\n[Network Error] {}".format(e))
        return False
    finally:
        if own_sock and sock is not None:
            try:
                sock.close()
            except Exception:
                pass


def create_auth_ipv6_packet(alg_ids, plaintext_str, src_ip, dst_ip, use_lib_lock=False):
    c_ids = (ctypes.c_int * 3)(*alg_ids)
    # 构造 64 字节明文，确保完整传递不被截断
    pt_bytes = plaintext_str.encode('utf-8').ljust(64, b'\0')
    pt_buf = (ctypes.c_uint8 * 64).from_buffer_copy(pt_bytes)
    out_buffer = ctypes.create_string_buffer(AUTH_PAYLOAD_LEN)
    if use_lib_lock:
        with lib_lock:
            ret = libauth.auth_generate_packet(ctypes.byref(c_ids), pt_buf, out_buffer)
    else:
        ret = libauth.auth_generate_packet(ctypes.byref(c_ids), pt_buf, out_buffer)
    if ret != 0:
        raise RuntimeError("auth_generate_packet failed, ret={}, alg_ids={}".format(ret, alg_ids))
    print_crypto_trace("Generate Trace")
    payload = out_buffer.raw[:AUTH_PAYLOAD_LEN]
    header = struct.pack("!I H B B 16s 16s",
        0x60000000, AUTH_PAYLOAD_LEN, AUTH_NEXT_HEADER, 64,
        ipv6_addr_to_bytes(src_ip), ipv6_addr_to_bytes(dst_ip))
    return header + payload


def is_own_echo(data):
    with last_sent_payload_lock:
        payload = last_sent_payload
    if payload and len(data) >= 4 and len(payload) >= 4:
        if data[:4] == payload[:4]:
            return True
    return False


def listen_for_re_auth(src_ip):
    """Channel 1: listen with IPv6 raw socket (Next Header=200)."""
    print("[IPv6 Listener] listening (next_header={}, addr={})...".format(AUTH_NEXT_HEADER, src_ip))
    try:
        sock = socket.socket(socket.AF_INET6, socket.SOCK_RAW, AUTH_NEXT_HEADER)
        sock.bind((src_ip, 0))
        sock.settimeout(1.0)
        while running:
            try:
                data, addr = sock.recvfrom(2048)
            except socket.timeout:
                continue
            if is_own_echo(data):
                continue
            print("\n[IPv6 Listener] received packet len={}, first20={}".format(len(data), data[:20].hex()))
            idx = data.find(b"CMD_")
            if idx < 0:
                continue
            signal = data[idx:].split(b'\0')[0].decode('utf-8', 'ignore')
            print("[IPv6 Listener] received auth control signal: {}".format(signal))
            handle_signal(signal)
            save_pcap("last_reauth_signal.pcap", data)
    except Exception as e:
        print("[IPv6 Listener Error] {}".format(e))


def listen_for_re_auth_udp():
    """Channel 2: listen for re-auth signals over UDP as a fallback."""
    print("[UDP Listener] listening on UDP port {}...".format(SIGNAL_UDP_PORT))
    try:
        sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("::", SIGNAL_UDP_PORT))
        sock.settimeout(1.0)
        while running:
            try:
                data, addr = sock.recvfrom(4096)
            except socket.timeout:
                continue
            signal = data.decode('utf-8', 'ignore')
            print("[UDP Listener] received auth control signal (from {}): {}".format(addr, signal))
            handle_signal(signal)
    except Exception as e:
        print("[UDP Listener Error] {}".format(e))


def stdin_rate_control_loop():
    """Stdin dynamic rate control: enter a number to switch pps."""
    global running
    if not sys.stdin:
        return
    print("\n[Rate Control] enter a number at runtime to change pps, e.g. 100, 500, 1000")
    print("[Rate Control] also supported: rate 1000 / pause / resume / status / quit")
    while running:
        try:
            line = sys.stdin.readline()
        except Exception:
            break
        if line == "":
            time.sleep(0.2)
            continue
        cmd = line.strip()
        if not cmd:
            continue
        lower = cmd.lower()

        if lower in ("q", "quit", "exit"):
            print("\n[Rate Control] quit command received")
            running = False
            rate_update_event.set()
            re_auth_event.set()
            break
        elif lower in ("help", "?"):
            print("\n[Rate Control] enter a number to change pps; pause to pause; resume to resume; status to show current state; quit to exit")
        elif lower == "status":
            pps, gen = get_rate_state()
            with ids_lock:
                ids_snapshot = current_ids[:]
            print("\n[Status] current_pps={:.3f}, rate_generation={}, current_algs={}".format(pps, gen, ids_snapshot))
        elif lower == "pause":
            set_current_pps(0.0, "stdin")
        elif lower == "resume":
            with rate_lock:
                resume_pps = previous_positive_pps if previous_positive_pps > 0 else 1.0
            set_current_pps(resume_pps, "stdin")
        elif lower.startswith("rate ") or lower.startswith("pps ") or lower.startswith("set "):
            parts = cmd.split()
            if len(parts) >= 2:
                set_current_pps(parts[1], "stdin")
            else:
                print("\n[Rate] usage: rate 1000")
        else:
            set_current_pps(cmd, "stdin")


def parse_args():
    parser = argparse.ArgumentParser(description="IPv6 auth client with dynamic pps control, Python3.5 compatible")
    parser.add_argument("--src", default="::1", help="source IPv6 address, default ::1")
    parser.add_argument("--dst", default="::1", help="destination IPv6 address, default ::1")
    parser.add_argument("--pool", default="11,12,13,21,22,23,31,32,33", help="algorithm pool, default enables all 9 algorithms")
    parser.add_argument("--count", type=int, default=0, help="total packets to send; 0 means unlimited, default 0")
    parser.add_argument("--pps", "--rate", dest="pps", type=float, default=1.0, help="initial global send rate in packets per second; 0 means start paused and wait for input, default 1")
    parser.add_argument("--threads", type=int, default=1, help="sender worker thread count, default 1")
    parser.add_argument("--queue-size", type=int, default=1024, help="internal packet task queue size, default 1024")
    parser.add_argument("--lib-lock", action="store_true", help="serialize libauth.auth_generate_packet calls; safer when libauth is not reentrant, but lowers throughput")
    parser.add_argument("--ifname", default=None, help="bind network interface, e.g. eth0; unset means no binding")
    parser.add_argument("--no-listen", action="store_true", help="disable IPv6/UDP re-auth signal listeners")
    parser.add_argument("--no-rate-input", action="store_true", help="disable stdin dynamic rate control thread")
    parser.add_argument("--trace", action="store_true", help="print per-packet Generate Trace; disabled by default to avoid interfering with stdin input")
    parser.add_argument("--verbose", action="store_true", help="print per-packet send details; disabled by default to avoid interfering with stdin input")
    parser.add_argument("--quiet", action="store_true", help="minimal output, suitable for high-pps tests")
    parser.add_argument("--progress", type=int, default=0, help="print progress every N packets; 0 disables progress output")
    args = parser.parse_args()

    if args.count < 0:
        parser.error("--count must not be less than 0")
    if args.pps < 0:
        parser.error("--pps must not be less than 0")
    if args.threads <= 0:
        parser.error("--threads must be greater than 0")
    if args.queue_size <= 0:
        parser.error("--queue-size must be greater than 0")
    return args


def wait_for_rate_or_time(target_time, observed_generation):
    """Wait until target time; return False if rate changes so the main loop can reschedule."""
    while running:
        pps, gen = get_rate_state()
        if gen != observed_generation:
            return False
        now = time.time()
        remaining = target_time - now
        if remaining <= 0:
            return True
        wait_time = remaining if remaining < 0.2 else 0.2
        if rate_update_event.wait(timeout=wait_time):
            rate_update_event.clear()
            pps2, gen2 = get_rate_state()
            if gen2 != observed_generation:
                return False
    return False


def wait_while_paused(observed_generation):
    """Pause sending while pps is 0 until a new positive rate is entered or exit."""
    while running:
        pps, gen = get_rate_state()
        if gen != observed_generation:
            return False
        if pps > 0:
            return True
        if rate_update_event.wait(timeout=0.2):
            rate_update_event.clear()
    return False


def print_send_summary(plan_count, sent_ok, send_fail, gen_fail, start_time, end_time):
    elapsed = end_time - start_time
    elapsed_ms = elapsed * 1000.0
    actual_pps = float(sent_ok) / elapsed if elapsed > 0 else 0.0
    avg_ms = elapsed_ms / float(sent_ok) if sent_ok > 0 else 0.0

    print("\n========== Send Summary ==========")
    if plan_count == 0:
        print("Planned total    : unlimited, interrupted by user")
    else:
        print("Planned total    : {}".format(plan_count))
    print("Sent OK          : {}".format(sent_ok))
    print("Send failed      : {}".format(send_fail))
    print("Generate failed  : {}".format(gen_fail))
    print("Elapsed time     : {:.3f} ms".format(elapsed_ms))
    print("Average per pkt  : {:.6f} ms".format(avg_ms))
    print("Actual send rate : {:.2f} pps".format(actual_pps))
    print("==============================")




def queue_put_with_stop(task_queue, item):
    while running:
        try:
            task_queue.put(item, timeout=0.2)
            return True
        except queue.Full:
            continue
    return False


def dispatch_packet_sequence(task_queue, args, worker_count):
    """Dispatch sequence numbers at the current global pps. Workers do generation and sending."""
    global running
    seq = 1
    next_send_time = time.time()
    last_seen_generation = None

    try:
        while running and (args.count == 0 or seq <= args.count):
            pps, gen = get_rate_state()

            if pps <= 0:
                last_seen_generation = gen
                wait_while_paused(gen)
                next_send_time = time.time()
                continue

            if gen != last_seen_generation:
                next_send_time = time.time()
                last_seen_generation = gen

            if not wait_for_rate_or_time(next_send_time, gen):
                continue

            if not queue_put_with_stop(task_queue, seq):
                break

            seq += 1
            # If workers or queue are slower than the requested rate, do not burst later.
            next_send_time = max(next_send_time + (1.0 / pps), time.time())
    finally:
        # Tell workers to stop after all dispatched work is consumed, or immediately on shutdown.
        for _ in range(worker_count):
            try:
                task_queue.put(None, timeout=0.2)
            except Exception:
                pass


def send_worker(worker_id, args, task_queue):
    global stats_sent_ok, stats_send_fail, stats_gen_fail, stats_generated, running

    try:
        send_sock = open_send_socket(args.ifname)
    except Exception as e:
        print("\n[Worker-{}] socket open failed: {}".format(worker_id, e))
        running = False
        rate_update_event.set()
        return

    local_ok = 0
    local_send_fail = 0
    local_gen_fail = 0
    local_generated = 0

    try:
        while running:
            try:
                seq = task_queue.get(timeout=0.2)
            except queue.Empty:
                continue

            if seq is None:
                break

            with ids_lock:
                ids_snapshot = current_ids[:]

            message = "Auth packet #{:06d}: verify identity, nonce, and tags!".format(seq)
            try:
                pkt = create_auth_ipv6_packet(ids_snapshot, message, args.src, args.dst, args.lib_lock)
                local_generated += 1
            except Exception as e:
                local_gen_fail += 1
                if not args.quiet:
                    print("\n[Generate Error] worker={} seq={} error={}".format(worker_id, seq, e))
                continue

            if send_packet(args.dst, pkt, send_sock, args.quiet):
                local_ok += 1
            else:
                local_send_fail += 1

            if args.verbose and not args.quiet:
                print("[Worker-{}] sent auth packet #{} | current_algs={} | plaintext={}".format(
                    worker_id, seq, ids_snapshot, message))
            elif args.progress > 0 and not args.quiet and seq % args.progress == 0:
                pps_now, _ = get_rate_state()
                with stats_lock:
                    total_ok = stats_sent_ok + local_ok
                    total_fail = stats_send_fail + local_send_fail
                print("[Client] dispatched {} packets | ok {} | failed {} | current_rate {:.3f} pps | current_algs {}".format(
                    seq, total_ok, total_fail, pps_now, ids_snapshot))
    finally:
        try:
            send_sock.close()
        except Exception:
            pass
        with stats_lock:
            stats_sent_ok += local_ok
            stats_send_fail += local_send_fail
            stats_gen_fail += local_gen_fail
            stats_generated += local_generated

if __name__ == "__main__":
    args = parse_args()
    src_addr, dst_addr = args.src, args.dst
    my_pool = args.pool

    if args.trace and not args.quiet:
        TRACE_ENABLED = True
    elif args.quiet:
        TRACE_ENABLED = False

    if is_full_algorithm_pool(my_pool):
        current_ids = DEFAULT_ALGS[:]
    else:
        current_ids = select_random_algs(my_pool)
    set_current_pps(args.pps, "startup argument")

    if not args.no_listen:
        t_ipv6 = threading.Thread(target=listen_for_re_auth, args=(src_addr,))
        t_ipv6.daemon = True
        t_ipv6.start()
        t_udp = threading.Thread(target=listen_for_re_auth_udp)
        t_udp.daemon = True
        t_udp.start()

    if not args.no_rate_input:
        t_rate = threading.Thread(target=stdin_rate_control_loop)
        t_rate.daemon = True
        t_rate.start()

    print("=== Adaptive Auth Client Started ===")
    print("Current algorithm pool: {}".format(my_pool))
    if is_full_algorithm_pool(my_pool):
        print("Pool mode: all 9 algorithms enabled; default 192-bit combo {}".format(current_ids))
    else:
        print("Pool mode: partial pool; startup algorithms selected from pool {}".format(current_ids))
    print("Attack signal: CMD_ATTACK_MODE or CMD_FORCE_ALGS:13,23,33")
    print("High-load signal: CMD_HIGH_LOAD or CMD_FORCE_ALGS:11,21,31")
    print("Normal-mode signal: CMD_NORMAL_MODE or CMD_FORCE_ALGS:12,22,32")
    print("IPv6 NextHeader: {}".format(AUTH_NEXT_HEADER))
    print("Total packets: {}".format("unlimited" if args.count == 0 else args.count))
    print("Sender worker threads: {}".format(args.threads))
    print("Task queue size: {}".format(args.queue_size))
    if args.lib_lock:
        print("libauth generation lock: enabled")
    else:
        print("libauth generation lock: disabled")
    if args.pps > 0:
        print("Initial send rate: {:.3f} pps; enter a new rate in stdin to change it dynamically".format(args.pps))
    else:
        print("Initial state: paused; enter a positive rate in stdin to start sending")
    if args.ifname:
        print("Bound interface: {}".format(args.ifname))
    if not args.no_listen:
        print("IPv6 signal channel: Next Header={}".format(AUTH_NEXT_HEADER))
        print("UDP signal channel: port {}".format(SIGNAL_UDP_PORT))
    if args.trace and args.threads > 1:
        print("[Warning] --trace with multiple sender threads may interleave trace output; use --threads 1 for trace debugging")
    if not args.quiet:
        print("Per-packet plaintext and trace are not printed by default; use --verbose or --trace for details")

    task_queue = queue.Queue(maxsize=args.queue_size)
    workers = []
    start_time = time.time()

    try:
        for tid in range(args.threads):
            t = threading.Thread(target=send_worker, args=(tid, args, task_queue))
            t.daemon = True
            workers.append(t)
            t.start()

        dispatcher = threading.Thread(target=dispatch_packet_sequence, args=(task_queue, args, args.threads))
        dispatcher.daemon = True
        dispatcher.start()

        dispatcher.join()
        for t in workers:
            t.join()

    except KeyboardInterrupt:
        running = False
        rate_update_event.set()
        re_auth_event.set()
        print("\nuser interrupted, exiting...")
        for _ in range(args.threads):
            try:
                task_queue.put_nowait(None)
            except Exception:
                pass
        for t in workers:
            try:
                t.join(timeout=1.0)
            except Exception:
                pass
    finally:
        running = False
        rate_update_event.set()
        re_auth_event.set()
        with stats_lock:
            final_ok = stats_sent_ok
            final_send_fail = stats_send_fail
            final_gen_fail = stats_gen_fail
        print_send_summary(args.count, final_ok, final_send_fail, final_gen_fail, start_time, time.time())

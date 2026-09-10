#!/usr/bin/env python3
"""
Real-world Traffic Generator for IPsec Testbed.
Simulates realistic inner application traffic dynamics:
- VoIP (RTP / G.711 / Opus pacing & jitter)
- Video Streaming (MPEG-TS / UDP bursts with periodic keyframe spikes)
- Web Browsing (HTTP GET/POST transactions with variable asset sizes and idle dwell times)
- WhatsApp / Chat (Sporadic short message bursts with idle gaps)
- Email (SMTP/IMAP text transactions with occasional MIME payloads)
- Bulk Data Transfer (TCP streaming)
- ICMP (Ping flows with normal and variable payload sizes)
- Background Noise (DNS, NTP, ARP, stray packets)
- Mixed (Concurrent browsing + chat)
"""

import socket
import time
import random
import argparse
import threading
import sys
import os

# Default communication ports
PORT_VOIP = 5004
PORT_VIDEO = 5006
PORT_WEB = 8080
PORT_CHAT = 5222
PORT_EMAIL = 2525
PORT_BULK = 5201
PORT_NOISE = 5353

def run_responder_server():
    """Runs background echo/sink listeners on the responder for all application protocols."""
    print("[Responder] Starting listener servers...")
    
    # UDP Sink Listener (VoIP, Video, Chat, Noise)
    def udp_sink(port, name):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(('0.0.0.0', port))
        while True:
            try:
                data, addr = sock.recvfrom(65535)
                # Echo back small acknowledgment for bidirectional realism
                if name in ["VOIP", "CHAT"] and random.random() < 0.3:
                    sock.sendto(b"ACK:" + data[:16], addr)
            except Exception:
                break

    for p, n in [(PORT_VOIP, "VOIP"), (PORT_VIDEO, "VIDEO"), (PORT_CHAT, "CHAT"), (PORT_NOISE, "NOISE")]:
        t = threading.Thread(target=udp_sink, args=(p, n), daemon=True)
        t.start()

    # TCP Echo/Web Listener (Web, Email, Bulk)
    def tcp_server(port, name):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(('0.0.0.0', port))
        sock.listen(10)
        while True:
            try:
                conn, _ = sock.accept()
                threading.Thread(target=handle_tcp_client, args=(conn, name), daemon=True).start()
            except Exception:
                break

    def handle_tcp_client(conn, name):
        try:
            while True:
                data = conn.recv(65536)
                if not data:
                    break
                if name == "WEB":
                    # Send realistic HTTP response payload
                    response = (
                        b"HTTP/1.1 200 OK\r\n"
                        b"Content-Type: text/html\r\n"
                        b"Server: Apache/2.4.58\r\n"
                        b"Content-Length: " + str(len(data) * 2).encode() + b"\r\n\r\n"
                        + (b"X" * (len(data) * 2))
                    )
                    conn.sendall(response)
                elif name == "EMAIL":
                    conn.sendall(b"250 OK Message accepted for delivery\r\n")
                elif name == "BULK":
                    conn.sendall(b"ACK" * (len(data) // 3))
        except Exception:
            pass
        finally:
            conn.close()

    for p, n in [(PORT_WEB, "WEB"), (PORT_EMAIL, "EMAIL"), (PORT_BULK, "BULK")]:
        t = threading.Thread(target=tcp_server, args=(p, n), daemon=True)
        t.start()

    print("[Responder] All listeners active. Ready for traffic.")
    # Keep main thread alive
    while True:
        time.sleep(3600)


def generate_voip_traffic(target_ip, duration_sec):
    """Simulates realistic VoIP RTP packet stream (G.711 / Opus codecs)."""
    print(f"[Traffic] Generating VoIP traffic to {target_ip} for {duration_sec}s...")
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    
    end_time = time.time() + duration_sec
    seq = 0
    while time.time() < end_time:
        # Standard G.711 / Opus frame: 160 to 240 bytes payload + 12 bytes RTP header
        payload_size = random.randint(160, 240)
        # Sequence number + timestamp + random payload
        ts_32 = int(time.time() * 8000) & 0xFFFFFFFF
        rtp_header = b"\x80\x00" + seq.to_bytes(2, 'big') + ts_32.to_bytes(4, 'big') + b"\x12\x34\x56\x78"
        payload = rtp_header + os.urandom(payload_size)
        
        try:
            sock.sendto(payload, (target_ip, PORT_VOIP))
        except Exception as e:
            pass
        
        seq = (seq + 1) % 65536
        # Pacing: ~20ms interval with realistic Gaussian jitter (±3ms)
        interval = max(0.010, random.gauss(0.020, 0.003))
        time.sleep(interval)
    sock.close()


def generate_video_traffic(target_ip, duration_sec):
    """Simulates UDP video streaming with regular P-frames and periodic I-frame burst spikes."""
    print(f"[Traffic] Generating Video Streaming traffic to {target_ip} for {duration_sec}s...")
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    
    end_time = time.time() + duration_sec
    last_iframe = 0
    
    while time.time() < end_time:
        now = time.time()
        # Every 1.0 to 1.5 seconds, send an I-frame burst (Keyframe)
        if now - last_iframe > random.uniform(1.0, 1.5):
            last_iframe = now
            # Keyframe burst: 15-30 full-size packets
            packets_in_burst = random.randint(15, 30)
            for _ in range(packets_in_burst):
                pkt = os.urandom(random.randint(1200, 1420))
                sock.sendto(pkt, (target_ip, PORT_VIDEO))
                time.sleep(0.001)
        else:
            # Regular P-frame / delta: 2-5 packets
            for _ in range(random.randint(2, 5)):
                pkt = os.urandom(random.randint(600, 1300))
                sock.sendto(pkt, (target_ip, PORT_VIDEO))
                time.sleep(0.002)
        
        time.sleep(random.uniform(0.030, 0.040)) # ~30 fps cadence
    sock.close()


def generate_web_traffic(target_ip, duration_sec):
    """Simulates Web browsing (HTTP GET/POST transactions with variable page resources and dwell time)."""
    print(f"[Traffic] Generating Web Browsing traffic to {target_ip} for {duration_sec}s...")
    end_time = time.time() + duration_sec
    
    while time.time() < end_time:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5.0)
            sock.connect((target_ip, PORT_WEB))
            
            # Initial HTML page request
            req = b"GET /index.html HTTP/1.1\r\nHost: " + target_ip.encode() + b"\r\nUser-Agent: Mozilla/5.0\r\n\r\n"
            sock.sendall(req)
            _ = sock.recv(4096)
            
            # Secondary resource requests (images/JS/CSS assets)
            for _ in range(random.randint(2, 8)):
                asset_path = f"/static/asset_{random.randint(1, 100)}.png".encode()
                req = b"GET " + asset_path + b" HTTP/1.1\r\nHost: " + target_ip.encode() + b"\r\n\r\n"
                sock.sendall(req)
                _ = sock.recv(8192)
                time.sleep(random.uniform(0.01, 0.08))
            
            sock.close()
        except Exception as e:
            pass
        
        # User think time between page navigations (0.5 to 2.0 seconds)
        time.sleep(random.uniform(0.5, 2.0))


def generate_chat_traffic(target_ip, duration_sec):
    """Simulates Instant Messaging / WhatsApp (intermittent short message bursts with idle pauses)."""
    print(f"[Traffic] Generating Chat/WhatsApp traffic to {target_ip} for {duration_sec}s...")
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    end_time = time.time() + duration_sec
    
    while time.time() < end_time:
        # Message burst: 1 to 4 short messages
        for _ in range(random.randint(1, 4)):
            # WhatsApp text or typing notification payload
            msg_size = random.randint(50, 280)
            msg = b"\x17\x03\x03" + os.urandom(msg_size)
            try:
                sock.sendto(msg, (target_ip, PORT_CHAT))
            except Exception:
                pass
            time.sleep(random.uniform(0.1, 0.4))
        
        # Idle pause between chat messages (1.5 to 4.0 seconds)
        time.sleep(random.uniform(1.5, 4.0))
    sock.close()


def generate_email_traffic(target_ip, duration_sec):
    """Simulates SMTP/IMAP transactions with text content and occasional attachments."""
    print(f"[Traffic] Generating Email traffic to {target_ip} for {duration_sec}s...")
    end_time = time.time() + duration_sec
    
    while time.time() < end_time:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5.0)
            sock.connect((target_ip, PORT_EMAIL))
            
            # SMTP handshake simulation
            sock.sendall(b"EHLO client.internal\r\n")
            _ = sock.recv(1024)
            sock.sendall(b"MAIL FROM:<sender@gov.in>\r\n")
            _ = sock.recv(1024)
            sock.sendall(b"RCPT TO:<recipient@gov.in>\r\n")
            _ = sock.recv(1024)
            sock.sendall(b"DATA\r\n")
            _ = sock.recv(1024)
            
            # Message body (text or MIME attachment)
            body_size = random.choice([500, 1500, 10000, 25000])
            sock.sendall(os.urandom(body_size) + b"\r\n.\r\n")
            _ = sock.recv(1024)
            
            sock.sendall(b"QUIT\r\n")
            sock.close()
        except Exception:
            pass
        
        time.sleep(random.uniform(1.0, 3.0))


def generate_bulk_traffic(target_ip, duration_sec):
    """Simulates bulk TCP file transfer / download."""
    print(f"[Traffic] Generating Bulk TCP traffic to {target_ip} for {duration_sec}s...")
    end_time = time.time() + duration_sec
    chunk = os.urandom(16384)
    
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5.0)
        sock.connect((target_ip, PORT_BULK))
        while time.time() < end_time:
            sock.sendall(chunk)
            _ = sock.recv(1024)
        sock.close()
    except Exception:
        pass


def generate_icmp_traffic(target_ip, duration_sec):
    """Generates ICMP ping flows with normal, small, and oversized payload packets."""
    print(f"[Traffic] Generating ICMP traffic to {target_ip} for {duration_sec}s...")
    end_time = time.time() + duration_sec
    sizes = [32, 64, 128, 512, 1000, 1400]
    
    while time.time() < end_time:
        size = random.choice(sizes)
        os.system(f"ping -c 1 -s {size} -W 1 {target_ip} > /dev/null 2>&1")
        time.sleep(random.uniform(0.1, 0.5))


def generate_background_noise(target_ip, duration_sec):
    """Injects real-world background network noise (DNS queries, NTP, ARP, stray packets)."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    end_time = time.time() + duration_sec
    
    while time.time() < end_time:
        # Stray DNS or NTP query
        payload = b"\x00\x01\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00" + os.urandom(random.randint(20, 80))
        try:
            sock.sendto(payload, (target_ip, PORT_NOISE))
        except Exception:
            pass
        time.sleep(random.uniform(0.2, 1.0))
    sock.close()


def generate_mixed_traffic(target_ip, duration_sec):
    """Runs concurrent Web browsing + Chat in parallel (highly realistic multi-app flow)."""
    print(f"[Traffic] Generating Mixed (Web + Chat) traffic to {target_ip} for {duration_sec}s...")
    t1 = threading.Thread(target=generate_web_traffic, args=(target_ip, duration_sec), daemon=True)
    t2 = threading.Thread(target=generate_chat_traffic, args=(target_ip, duration_sec), daemon=True)
    t1.start()
    t2.start()
    t1.join()
    t2.join()


def main():
    parser = argparse.ArgumentParser(description="IPsec Testbed Traffic Generator")
    parser.add_argument("--mode", choices=["responder", "client"], required=True, help="Run as responder sink or client generator")
    parser.add_argument("--target-ip", default="172.28.0.3", help="Target responder IP")
    parser.add_argument("--traffic", choices=["voip", "video", "web", "chat", "email", "bulk", "icmp", "mixed"], default="voip", help="Traffic profile to generate")
    parser.add_argument("--duration", type=int, default=10, help="Traffic generation duration in seconds")
    parser.add_argument("--noise", action="store_true", help="Inject concurrent background network noise")

    args = parser.parse_args()

    if args.mode == "responder":
        run_responder_server()
        return

    # Start optional background noise thread
    if args.noise:
        threading.Thread(target=generate_background_noise, args=(args.target_ip, args.duration), daemon=True).start()

    # Run chosen traffic profile
    profile_map = {
        "voip": generate_voip_traffic,
        "video": generate_video_traffic,
        "web": generate_web_traffic,
        "chat": generate_chat_traffic,
        "email": generate_email_traffic,
        "bulk": generate_bulk_traffic,
        "icmp": generate_icmp_traffic,
        "mixed": generate_mixed_traffic
    }

    generator = profile_map.get(args.traffic, generate_voip_traffic)
    generator(args.target_ip, args.duration)
    print(f"[Traffic] Completed {args.traffic} profile.")


if __name__ == "__main__":
    main()

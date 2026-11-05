# Packet capture engine - The Sniffer
# Written by: @dukebismaya

from scapy.all import IP, sniff, TCP
import threading
import queue
import logging

logger = logging.getLogger("PySentry.capture")

MAX_QUEUE_SIZE = 10000


class PacketCapture:
    def __init__(self) -> None:
        self.packet_queue = queue.Queue(maxsize=MAX_QUEUE_SIZE)
        self.stop_capture = threading.Event()

    def packet_callback(self, packet):
        # We only care about IP and TCP
        if IP in packet and TCP in packet:
            try:
                self.packet_queue.put_nowait(packet)
            except queue.Full:
                logger.warning("Packet queue full (%d). Dropping packet.", MAX_QUEUE_SIZE)

    def start_capture(self, interface="eth0"):
        def capture_thread():
            try:
                sniff(
                    iface=interface,
                    prn=self.packet_callback,
                    store=0,
                    stop_filter=lambda _: self.stop_capture.is_set(),
                )
            except OSError as e:
                logger.error("Failed to start capture on '%s': %s", interface, e)
            except PermissionError:
                logger.error(
                    "Permission denied. Packet sniffing requires Administrator/root privileges."
                )

        self.thread = threading.Thread(target=capture_thread, daemon=True)
        self.thread.start()
        logger.info("Packet capture started on interface '%s'.", interface)

    def stop(self):
        self.stop_capture.set()
        logger.info("Packet capture stopped.")

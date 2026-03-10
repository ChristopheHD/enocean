## 2025-02-14 - Remote DoS via Malformed Packets
**Vulnerability:** A Remote Denial of Service (DoS) vulnerability existed in the packet parsing logic. Malformed packets with valid CRC but insufficient internal data triggered `IndexError` in communicator threads, causing them to terminate.
**Learning:** Packet parsing logic must always perform bounds checking before index-based access, even if the packet has passed initial validation (like CRC). High-level communicator loops should be resilient to exceptions raised during packet processing.
**Prevention:** 1. Always validate list/buffer lengths before accessing specific indices. 2. Wrap packet instantiation and parsing in `try...except` blocks to prevent unexpected malformations from crashing the service.

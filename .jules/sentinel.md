## 2026-02-03 - [TCP Exposure and DoS Mitigation]
**Vulnerability:** TCPCommunicator listened on all interfaces by default and had no buffer limit, leading to potential unauthorized access and DoS via memory exhaustion.
**Learning:** Defaulting to all interfaces (`''`) in network listeners is a security risk. Making the host mandatory ensures users consciously choose the binding interface. Additionally, found a Python pitfall where logging a tuple using `"%s" % (addr)` fails with `TypeError` because the tuple is unpacked; it must be `"%s" % (addr,)`.
**Prevention:** Always require binding address for network listeners and implement resource limits (buffer sizes) for all external inputs. Use defensive string formatting for logging objects that might be tuples.

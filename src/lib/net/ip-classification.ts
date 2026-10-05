/**
 * Address classification: is a literal IP address safe to connect to?
 *
 * Pure, and deliberately NOT behind `server-only`. These are total
 * functions over strings with no I/O and no environment, which makes them
 * the part of the SSRF defence that can be exercised directly in a unit
 * test — and the part most worth exercising, because a single wrong
 * boundary here silently reopens the hole. Keeping them importable without
 * a module stub is the point.
 *
 * The ranges refused, and why each matters:
 *
 *   IPv4  0.0.0.0/8        "this host on this network"
 *         10/8, 172.16/12, 192.168/16   RFC 1918 private
 *         127/8            loopback
 *         169.254/16       link-local — this is the cloud metadata range
 *         100.64/10        RFC 6598 carrier-grade NAT
 *         198.18/15        benchmarking
 *         224/4 and above  multicast, reserved, broadcast
 *
 *   IPv6  ::, ::1          unspecified and loopback
 *         fc00::/7         unique-local
 *         fe80::/10        link-local
 *         ff00::/8         multicast
 *         2001:db8::/32    documentation
 *         100::/64         discard-only
 *         ::ffff:0:0/96    IPv4-mapped — judged on the embedded IPv4
 *         64:ff9b::/96     IPv4-translated — likewise
 *
 * The IPv4-mapped and IPv4-translated cases are the ones that catch people
 * out: `::ffff:169.254.169.254` is a perfectly valid IPv6 address that
 * reaches the metadata service, and a checker that only pattern-matches
 * IPv6 prefixes waves it straight through.
 */
import { isIP } from "node:net";

function ipv4Private(address: string): boolean {
  const parts = address.split(".").map(Number);
  if (parts.length !== 4 || parts.some((n) => !Number.isInteger(n) || n < 0 || n > 255)) {
    return true; // unparseable is not public
  }
  const [a, b] = parts as [number, number, number, number];

  if (a === 0) return true; // "this host on this network"
  if (a === 10) return true; // RFC 1918
  if (a === 127) return true; // loopback
  if (a === 169 && b === 254) return true; // link-local, incl. cloud metadata
  if (a === 172 && b >= 16 && b <= 31) return true; // RFC 1918
  if (a === 192 && b === 168) return true; // RFC 1918
  if (a === 100 && b >= 64 && b <= 127) return true; // CGNAT, RFC 6598
  if (a === 198 && (b === 18 || b === 19)) return true; // benchmarking
  if (a >= 224) return true; // multicast, reserved, broadcast
  return false;
}

/** Expands any valid IPv6 textual form to its 16 bytes. */
function ipv6Bytes(address: string): number[] | null {
  let text = address;

  // An embedded IPv4 tail ("::ffff:192.0.2.1") becomes two hextets.
  const tail = /:(\d+\.\d+\.\d+\.\d+)$/.exec(text);
  if (tail?.[1]) {
    const octets = tail[1].split(".").map(Number);
    if (octets.length !== 4 || octets.some((n) => !Number.isInteger(n) || n > 255)) return null;
    const hi = ((octets[0] as number) << 8) | (octets[1] as number);
    const lo = ((octets[2] as number) << 8) | (octets[3] as number);
    text = `${text.slice(0, tail.index)}:${hi.toString(16)}:${lo.toString(16)}`;
  }

  const [head, rest, ...extra] = text.split("::");
  if (extra.length > 0) return null;

  const split = (part: string | undefined) =>
    part && part.length > 0 ? part.split(":") : [];

  const left = split(head);
  const right = split(rest);
  const fill = rest === undefined ? 0 : 8 - left.length - right.length;
  if (fill < 0) return null;

  const hextets = [...left, ...Array<string>(fill).fill("0"), ...right];
  if (hextets.length !== 8) return null;

  const bytes: number[] = [];
  for (const hextet of hextets) {
    const value = Number.parseInt(hextet || "0", 16);
    if (!Number.isInteger(value) || value < 0 || value > 0xffff) return null;
    bytes.push((value >> 8) & 0xff, value & 0xff);
  }
  return bytes;
}

function ipv6Private(address: string): boolean {
  const b = ipv6Bytes(address);
  if (!b) return true;

  const allZero = b.every((byte) => byte === 0);
  if (allZero) return true; // ::
  if (b.slice(0, 15).every((byte) => byte === 0) && b[15] === 1) return true; // ::1

  // IPv4-mapped (::ffff:0:0/96) and IPv4-translated (64:ff9b::/96): the
  // embedded v4 address is the thing that must be judged.
  const mapped =
    b.slice(0, 10).every((byte) => byte === 0) && b[10] === 0xff && b[11] === 0xff;
  const translated = b[0] === 0x00 && b[1] === 0x64 && b[2] === 0xff && b[3] === 0x9b;
  if (mapped || translated) {
    return ipv4Private(`${b[12]}.${b[13]}.${b[14]}.${b[15]}`);
  }

  if (((b[0] as number) & 0xfe) === 0xfc) return true; // fc00::/7 unique-local
  if (b[0] === 0xfe && ((b[1] as number) & 0xc0) === 0x80) return true; // fe80::/10
  if (b[0] === 0xff) return true; // ff00::/8 multicast
  if (b[0] === 0x20 && b[1] === 0x01 && b[2] === 0x0d && b[3] === 0xb8) return true; // 2001:db8::/32
  if (b[0] === 0x01 && b[1] === 0x00 && b.slice(2, 8).every((x) => x === 0)) return true; // 100::/64

  return false;
}

/** True when the literal address is safe to connect to from the server. */
export function isPublicAddress(address: string): boolean {
  const family = isIP(address);
  if (family === 4) return !ipv4Private(address);
  if (family === 6) return !ipv6Private(address);
  return false;
}

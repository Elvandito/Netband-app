package com.netband.app

import io.flutter.embedding.android.FlutterActivity
import io.flutter.embedding.engine.FlutterEngine
import io.flutter.plugin.common.MethodChannel
import java.util.concurrent.TimeUnit

class MainActivity : FlutterActivity() {
    private val channel = "com.netband.app/network"
    private val ipRegex = Regex("^(?:25[0-5]|2[0-4]\\d|1?\\d?\\d)(?:\\.(?:25[0-5]|2[0-4]\\d|1?\\d?\\d)){3}$")

    override fun configureFlutterEngine(flutterEngine: FlutterEngine) {
        super.configureFlutterEngine(flutterEngine)
        MethodChannel(flutterEngine.dartExecutor.binaryMessenger, channel).setMethodCallHandler { call, result ->
            Thread {
                try {
                    val value: Any = when (call.method) {
                        "status" -> networkStatus(false)
                        "scan" -> networkStatus(true)
                        "applyLimit" -> {
                            val ip = checkedIp(call.argument<String>("ip"))
                            val rate = call.argument<Int>("rateKbit") ?: 2048
                            require(rate in 32..1_000_000) { "Rate must be 32–1,000,000 kbit/s" }
                            commandLimit(ip, rate)
                        }
                        "block" -> commandBlock(checkedIp(call.argument<String>("ip")))
                        "unlimit" -> commandUnlimit(checkedIp(call.argument<String>("ip")))
                        "cleanup" -> cleanup()
                        else -> throw IllegalArgumentException("Unknown method: ${call.method}")
                    }
                    runOnUiThread { result.success(value) }
                } catch (e: Exception) {
                    runOnUiThread { result.error("NETBAND_ERROR", e.message ?: "Operation failed", null) }
                }
            }.start()
        }
    }

    private fun checkedIp(ip: String?): String {
        require(ip != null && ipRegex.matches(ip)) { "Invalid IPv4 address" }
        require(!ip.startsWith("127.") && !ip.startsWith("0.")) { "Loopback/unspecified addresses are not valid targets" }
        return ip
    }

    private data class Cmd(val code: Int, val output: String)
    private fun root(script: String, timeoutSec: Long = 12): Cmd {
        val p = ProcessBuilder("su", "-c", script).redirectErrorStream(true).start()
        val finished = p.waitFor(timeoutSec, TimeUnit.SECONDS)
        if (!finished) { p.destroyForcibly(); throw IllegalStateException("Root command timed out") }
        val out = p.inputStream.bufferedReader().use { it.readText() }.trim()
        return Cmd(p.exitValue(), out)
    }
    private fun quote(s: String) = "'" + s.replace("'", "'\\''") + "'"
    private fun runOk(script: String): String {
        val c = root(script)
        if (c.code != 0) throw IllegalStateException(c.output.ifBlank { "Command failed (${c.code}). Check root, tc and iptables support." })
        return c.output
    }

    private fun networkStatus(doScan: Boolean): Map<String, Any> {
        val rootAvailable = try { root("id", 4).let { it.code == 0 && it.output.contains("uid=0") } } catch (_: Exception) { false }
        val iface = try { root("ip -o route show default 2>/dev/null | awk '{print \$5}' | head -n1", 5).output.trim().ifBlank { root("getprop wifi.interface", 3).output.trim().ifBlank { "wlan0" } } } catch (_: Exception) { "wlan0" }
        val safeIface = iface.trim().takeIf { it.matches(Regex("^[a-zA-Z0-9_.:-]{1,32}$")) } ?: "wlan0"
        if (!rootAvailable) return mapOf("root" to false, "interface" to safeIface, "gateway" to "—", "localIp" to "—", "devices" to emptyList<Map<String, String>>())
        if (doScan) {
            // Populate the kernel neighbor cache on the local /24 without requiring Termux/Python.
            val addr = root("ip -o -4 addr show dev ${quote(safeIface)} | awk '{print \$4}' | head -n1", 4).output.substringBefore('/')
            if (addr.matches(ipRegex)) {
                val prefix = addr.substringBeforeLast('.')
                root("for n in \$(seq 1 254); do (ping -c 1 -W 1 \"$prefix.\$n\" >/dev/null 2>&1) & [ \$(jobs -p | wc -l) -ge 24 ] && wait; done; wait; ip neigh show dev ${quote(safeIface)}", 35)
            }
        }
        val route = root("ip -o route show default 2>/dev/null | head -n1", 4).output
        val gateway = Regex("\\bvia\\s+(\\d+(?:\\.\\d+){3})").find(route)?.groupValues?.get(1) ?: "—"
        val local = root("ip -o -4 addr show dev ${quote(safeIface)} 2>/dev/null | awk '{print \$4}' | head -n1", 4).output.substringBefore('/')
        val neigh = root("ip neigh show dev ${quote(safeIface)} 2>/dev/null", 5).output
        val devices = neigh.lines().mapNotNull { line ->
            val ip = line.trim().split(Regex("\\s+" )).firstOrNull() ?: return@mapNotNull null
            if (!ipRegex.matches(ip)) return@mapNotNull null
            val mac = Regex("lladdr\\s+([0-9a-fA-F:]{17})").find(line)?.groupValues?.get(1) ?: "—"
            val state = line.trim().split(Regex("\\s+")).lastOrNull() ?: "UNKNOWN"
            mapOf("ip" to ip, "mac" to mac, "state" to state)
        }.distinctBy { it["ip"] }.sortedBy { it["ip"] }
        return mapOf("root" to true, "interface" to safeIface, "gateway" to gateway, "localIp" to local, "devices" to devices)
    }

    private fun classId(ip: String): Int {
        val octet = ip.substringAfterLast('.').toInt()
        return 10 + (octet % 240)
    }
    private fun targetClass(ip: String) = "1:${classId(ip).toString(16)}"

    private fun commandLimit(ip: String, rate: Int): Map<String, Any> {
        val iface = root("ip -o route show default | awk '{print \$5}' | head -n1", 4).output.trim().ifBlank { "wlan0" }
        require(iface.matches(Regex("^[a-zA-Z0-9_.:-]{1,32}$"))) { "Could not determine network interface" }
        val cls = targetClass(ip)
        val prio = classId(ip)
        val marker = "/data/local/tmp/netband_owns_htb_" + iface.replace(Regex("[^a-zA-Z0-9]"), "_")
        val setup = """
            set -e
            if ! tc qdisc show dev ${quote(iface)} | grep -q 'qdisc htb 1:'; then
              if tc qdisc show dev ${quote(iface)} | grep -q 'qdisc .* root'; then echo 'Existing root qdisc detected; refusing to overwrite another QoS configuration.'; exit 23; fi
              tc qdisc add dev ${quote(iface)} root handle 1: htb default 1
              tc class add dev ${quote(iface)} parent 1: classid 1:1 htb rate 1000mbit ceil 1000mbit
              touch ${quote(marker)}
            fi
            tc class replace dev ${quote(iface)} parent 1: classid ${quote(cls)} htb rate ${rate}kbit ceil ${rate}kbit burst 64k cburst 64k
            tc filter replace dev ${quote(iface)} protocol ip parent 1: prio $prio u32 match ip dst ${quote(ip)}/32 flowid ${quote(cls)}
            tc filter replace dev ${quote(iface)} protocol ip parent 1: prio ${prio + 1} u32 match ip src ${quote(ip)}/32 flowid ${quote(cls)}
        """.trimIndent()
        val c = root(setup, 12)
        if (c.code != 0) throw IllegalStateException(c.output.ifBlank { "tc shaping failed. This kernel/interface may not support HTB." })
        return mapOf("ok" to true, "message" to "Limit applied: $rate kbit/s on $iface (traffic routed through this phone only).")
    }

    private fun commandBlock(ip: String): Map<String, Any> {
        val script = """
            set -e
            iptables -C FORWARD -s ${quote(ip)} -j DROP 2>/dev/null || iptables -I FORWARD 1 -s ${quote(ip)} -j DROP
            iptables -C FORWARD -d ${quote(ip)} -j DROP 2>/dev/null || iptables -I FORWARD 1 -d ${quote(ip)} -j DROP
            ip6tables -V >/dev/null 2>&1 || true
        """.trimIndent()
        runOk(script)
        return mapOf("ok" to true, "message" to "Forwarded traffic to/from $ip is blocked on this phone. This is not a router-wide block.")
    }

    private fun commandUnlimit(ip: String): Map<String, Any> {
        val iface = root("ip -o route show default | awk '{print \$5}' | head -n1", 4).output.trim().ifBlank { "wlan0" }
        val cls = targetClass(ip)
        val prio = classId(ip)
        val script = """
            tc filter del dev ${quote(iface)} protocol ip parent 1: prio $prio 2>/dev/null || true
            tc filter del dev ${quote(iface)} protocol ip parent 1: prio ${prio + 1} 2>/dev/null || true
            tc class del dev ${quote(iface)} classid ${quote(cls)} 2>/dev/null || true
            iptables -D FORWARD -s ${quote(ip)} -j DROP 2>/dev/null || true
            iptables -D FORWARD -d ${quote(ip)} -j DROP 2>/dev/null || true
            echo 'NetBand rules removed for ${ip}'
        """.trimIndent()
        return mapOf("ok" to true, "message" to runOk(script))
    }

    private fun cleanup(): Map<String, Any> {
        val iface = root("ip -o route show default | awk '{print \$5}' | head -n1", 4).output.trim().ifBlank { "wlan0" }
        val marker = "/data/local/tmp/netband_owns_htb_" + iface.replace(Regex("[^a-zA-Z0-9]"), "_")
        val script = "if [ -f ${quote(marker)} ]; then tc qdisc del dev ${quote(iface)} root 2>/dev/null || true; rm -f ${quote(marker)}; fi; iptables-save 2>/dev/null | grep -E 'FORWARD.*-j DROP' || true; echo 'Owned NetBand HTB qdisc removed if present.'"
        return mapOf("ok" to true, "message" to runOk(script))
    }
}

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

void main() => runApp(const NetBandApp());

const channel = MethodChannel('com.netband.app/network');
const bg = Color(0xFF0B1017);
const panel = Color(0xFF141C27);
const accent = Color(0xFF77E0B5);

class NetBandApp extends StatelessWidget {
  const NetBandApp({super.key});
  @override
  Widget build(BuildContext context) => MaterialApp(
        debugShowCheckedModeBanner: false,
        title: 'NetBand',
        theme: ThemeData(
          brightness: Brightness.dark,
          scaffoldBackgroundColor: bg,
          colorScheme: ColorScheme.fromSeed(seedColor: accent, brightness: Brightness.dark),
          useMaterial3: true,
          inputDecorationTheme: InputDecorationTheme(
            filled: true, fillColor: bg, border: OutlineInputBorder(borderRadius: BorderRadius.circular(12)),
          ),
        ),
        home: const Dashboard(),
      );
}

class Device {
  final String ip, mac, state;
  const Device(this.ip, this.mac, this.state);
  factory Device.fromMap(Map<dynamic, dynamic> m) => Device('${m['ip'] ?? ''}', '${m['mac'] ?? '—'}', '${m['state'] ?? 'UNKNOWN'}');
}

class Dashboard extends StatefulWidget {
  const Dashboard({super.key});
  @override
  State<Dashboard> createState() => _DashboardState();
}

class _DashboardState extends State<Dashboard> {
  bool busy = false, root = false;
  String iface = '—', gateway = '—', localIp = '—', message = 'Ready';
  List<Device> devices = [];
  final Map<String, String> limits = {};

  Future<void> refresh({bool scan = false}) async {
    setState(() { busy = true; message = scan ? 'Scanning local network…' : 'Refreshing network…'; });
    try {
      final result = Map<dynamic, dynamic>.from(await channel.invokeMethod(scan ? 'scan' : 'status'));
      root = result['root'] == true;
      iface = '${result['interface'] ?? '—'}'; gateway = '${result['gateway'] ?? '—'}'; localIp = '${result['localIp'] ?? '—'}';
      devices = (result['devices'] as List? ?? []).map((e) => Device.fromMap(Map<dynamic, dynamic>.from(e))).toList();
      message = '${result['message'] ?? '${devices.length} device(s) found'}';
    } on PlatformException catch (e) { message = e.message ?? 'Backend error'; }
    catch (e) { message = 'Unable to read network: $e'; }
    if (mounted) setState(() => busy = false);
  }

  Future<void> action(String method, Device d, {int? rate}) async {
    setState(() { busy = true; message = 'Applying network rule to ${d.ip}…'; });
    try {
      final result = Map<dynamic, dynamic>.from(await channel.invokeMethod(method, {'ip': d.ip, if (rate != null) 'rateKbit': rate}));
      message = '${result['message'] ?? 'Done'}';
      if (method == 'applyLimit' && rate != null) limits[d.ip] = '$rate kbit/s';
      if (method == 'unlimit') limits.remove(d.ip);
    } on PlatformException catch (e) { message = e.message ?? 'Command failed'; }
    catch (e) { message = 'Command failed: $e'; }
    await refresh();
  }

  Future<void> showLimit(Device d) async {
    final controller = TextEditingController(text: '2048');
    final rate = await showDialog<int>(context: context, builder: (context) => AlertDialog(
      title: Text('Limit ${d.ip}'),
      content: TextField(controller: controller, autofocus: true, keyboardType: TextInputType.number,
        decoration: const InputDecoration(labelText: 'Rate (kbit/s)', hintText: '2048'),
      ),
      actions: [TextButton(onPressed: () => Navigator.pop(context), child: const Text('Cancel')),
        FilledButton(onPressed: () { final n = int.tryParse(controller.text.trim()); if (n != null && n > 0) Navigator.pop(context, n); }, child: const Text('Apply'))],
    ));
    controller.dispose();
    if (rate != null) await action('applyLimit', d, rate: rate);
  }

  Future<void> confirmBlock(Device d) async {
    final ok = await showDialog<bool>(context: context, builder: (context) => AlertDialog(
      title: const Text('Block device?'), content: Text('Add firewall DROP rules for ${d.ip} on traffic forwarded through this phone?'),
      actions: [TextButton(onPressed: () => Navigator.pop(context, false), child: const Text('Cancel')),
        FilledButton(onPressed: () => Navigator.pop(context, true), child: const Text('Block'))],
    ));
    if (ok == true) await action('block', d);
  }

  @override
  void initState() { super.initState(); refresh(); }

  @override
  Widget build(BuildContext context) => Scaffold(
    appBar: AppBar(title: const Text('NetBand', style: TextStyle(fontWeight: FontWeight.w800, letterSpacing: -.5)),
      actions: [IconButton(onPressed: busy ? null : () => refresh(scan: true), icon: const Icon(Icons.radar), tooltip: 'Scan LAN')],),
    body: RefreshIndicator(onRefresh: () => refresh(scan: true), child: ListView(padding: const EdgeInsets.fromLTRB(16, 4, 16, 28), children: [
      Container(padding: const EdgeInsets.all(18), decoration: BoxDecoration(color: panel, borderRadius: BorderRadius.circular(22),
        border: Border.all(color: accent.withValues(alpha: .18))),
        child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
          Row(children: [Container(width: 10, height: 10, decoration: BoxDecoration(color: root ? accent : Colors.orangeAccent, shape: BoxShape.circle)), const SizedBox(width: 9),
            Text(root ? 'ROOT ACCESS AVAILABLE' : 'ROOT ACCESS REQUIRED', style: TextStyle(color: root ? accent : Colors.orangeAccent, fontSize: 11, fontWeight: FontWeight.bold, letterSpacing: 1.1))]),
          const SizedBox(height: 18), const Text('Local network', style: TextStyle(color: Colors.white60)),
          const SizedBox(height: 4), Text(iface, style: const TextStyle(fontSize: 27, fontWeight: FontWeight.w800)),
          const SizedBox(height: 16), Row(children: [Expanded(child: _metric('LOCAL IP', localIp)), Expanded(child: _metric('GATEWAY', gateway))]),
        ])),
      const SizedBox(height: 18),
      Row(children: [const Expanded(child: Text('Connected devices', style: TextStyle(fontSize: 19, fontWeight: FontWeight.w800))),
        Text('${devices.length}', style: const TextStyle(color: accent, fontWeight: FontWeight.bold)), const SizedBox(width: 8),
        IconButton(onPressed: busy ? null : () => refresh(scan: true), icon: const Icon(Icons.refresh))]),
      if (busy) const LinearProgressIndicator(minHeight: 2),
      if (devices.isEmpty) Container(padding: const EdgeInsets.all(24), decoration: BoxDecoration(color: panel, borderRadius: BorderRadius.circular(18)),
        child: const Column(children: [Icon(Icons.devices_other, size: 34, color: Colors.white38), SizedBox(height: 10), Text('No devices detected'), SizedBox(height: 4), Text('Tap scan to read the Android neighbor table.', textAlign: TextAlign.center, style: TextStyle(color: Colors.white54))])),
      ...devices.map((d) => _deviceCard(d)),
      const SizedBox(height: 16),
      Container(padding: const EdgeInsets.all(14), decoration: BoxDecoration(color: panel, borderRadius: BorderRadius.circular(14)),
        child: Row(crossAxisAlignment: CrossAxisAlignment.start, children: [const Icon(Icons.info_outline, color: accent, size: 20), const SizedBox(width: 10), Expanded(child: Text(message, style: const TextStyle(color: Colors.white70))) ])),
      const SizedBox(height: 10), const Text('Important: controls affect packets routed through this Android device. They do not automatically control other clients on a normal Wi-Fi LAN unless this phone is in the forwarding path.', style: TextStyle(color: Colors.white38, fontSize: 12, height: 1.45)),
    ])),
    floatingActionButton: FloatingActionButton.extended(onPressed: busy ? null : () => refresh(scan: true), icon: const Icon(Icons.radar), label: const Text('Scan LAN')),
  );

  Widget _metric(String label, String value) => Column(crossAxisAlignment: CrossAxisAlignment.start, children: [Text(label, style: const TextStyle(fontSize: 10, color: Color(0x73FFFFFF), letterSpacing: 1)), const SizedBox(height: 5), Text(value, style: const TextStyle(fontSize: 14, fontWeight: FontWeight.w600))]);

  Widget _deviceCard(Device d) => Card(margin: const EdgeInsets.only(bottom: 10), shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(17)), child: Padding(padding: const EdgeInsets.all(14), child: Column(children: [
    Row(children: [Container(width: 42, height: 42, decoration: BoxDecoration(color: accent.withValues(alpha: .10), borderRadius: BorderRadius.circular(13)), child: const Icon(Icons.devices, color: accent)), const SizedBox(width: 12),
      Expanded(child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [Text(d.ip, style: const TextStyle(fontSize: 15, fontWeight: FontWeight.bold)), const SizedBox(height: 3), Text('${d.mac}  ·  ${d.state}', style: const TextStyle(color: Colors.white54, fontSize: 11))])),
      if (limits.containsKey(d.ip)) Container(padding: const EdgeInsets.symmetric(horizontal: 9, vertical: 5), decoration: BoxDecoration(color: accent.withValues(alpha: .12), borderRadius: BorderRadius.circular(8)), child: Text(limits[d.ip]!, style: const TextStyle(color: accent, fontSize: 10))),
    ]), const SizedBox(height: 12), Row(children: [Expanded(child: OutlinedButton.icon(onPressed: busy ? null : () => showLimit(d), icon: const Icon(Icons.speed, size: 16), label: const Text('Limit'))), const SizedBox(width: 8),
      Expanded(child: OutlinedButton.icon(onPressed: busy ? null : () => confirmBlock(d), icon: const Icon(Icons.block, size: 16), label: const Text('Block'))), const SizedBox(width: 8),
      IconButton.filledTonal(onPressed: busy ? null : () => action('unlimit', d), icon: const Icon(Icons.restart_alt), tooltip: 'Remove NetBand rules')])
  ])));
}

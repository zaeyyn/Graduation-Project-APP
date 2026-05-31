class LinkEntry {
  final String domain;
  final String verdict; // SAFE / DANGER / WARN
  final DateTime time;

  LinkEntry({
    required this.domain,
    required this.verdict,
    required this.time,
  });

  Map<String, dynamic> toJson() => {
        'domain': domain,
        'verdict': verdict,
        'time': time.toIso8601String(),
      };

  factory LinkEntry.fromJson(Map<String, dynamic> json) => LinkEntry(
        domain: json['domain'],
        verdict: json['verdict'],
        time: DateTime.parse(json['time']),
      );
}
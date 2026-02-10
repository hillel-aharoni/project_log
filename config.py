# הגדרות לניתוח תעבורת רשת

# פורטים רגישים שעלולים להעיד על איומי אבטחה**
SENSITIVE_PORTS = {
    '22': 'SSH',      # # SSH (Secure Shell) – שליטה מרחוק
    '23': 'Telnet',   # שליטה מרחוק ללא הצפנה – מסוכן
    '3389': 'RDP'     # פרוטוקול שולחן עבודה מרוחק (RDP) – שליטה מרחוק ב־Windows
}

# טווחי כתובות IP פנימיים (רשתות פרטיות)
INTERNAL_IP_RANGES = [
    '192.168.',
    '10.'
]

# סף לזיהוי חבילות גדולות (בבייטים)
LARGE_PACKET_THRESHOLD = 5000

# שעות פעילות בלילה (פורמט 24 שעות)
NIGHT_START_HOUR = 0
NIGHT_END_HOUR = 6

# סוגי חשדות
SUSPICION_TYPES = {
    'EXTERNAL_IP': 'External IP address',
    'SENSITIVE_PORT': 'Traffic on sensitive port',
    'LARGE_PACKET': 'Large packet size',
    'NIGHT_ACTIVITY': 'Activity during night hours'
}
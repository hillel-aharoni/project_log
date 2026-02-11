def extract_external_ips(data):
    """
    מוציא כתובות IP חיצוניות מנתוני תעבורת רשת.
מחזיר:
    list: רשימת כתובות חיצוניות (שאינן מתחילות ב־192.168 או 10.)
    """
    external_ips = []
    for row in data:
        if len(row) >= 2:  # וודא שיש לנו לפחות חותמת זמן (timestamp) וכתובת IP מקורית (source_ip)
            source_ip = row[1]
            # בדוק אם כתובת ה‑IP **לא** מתחילה ב‑192.168 או 10.
            if not (source_ip.startswith('192.168.') or source_ip.startswith('10.')):
                external_ips.append(source_ip)
    return external_ips


def filter_sensitive_ports(data):
    """
    מסנן תעבורה לפי פורטים רגישים (22, 23, 3389)

    ארגומנטים:
        data (list): נתוני תעבורת רשת כרשימה של רשימות

    מחזיר:
        list: רשימת שורות עם תעבורה על פורטים רגישים
    """

    sensitive_ports = {'22', '23', '3389'}
    sensitive_traffic = [row for row in data
                         if len(row) >= 4 and row[3] in sensitive_ports]
    return sensitive_traffic


def filter_large_packets(data):
    """
    מסנן חבילות הגדולות מ‑5000 בתים.
    ארגומנטים:   נתוני תעבורת רשת כרשימה
    מחזיר:  רשימה עם חבילות הגדולות מ‑5000 בתים
    """
    large_packets = [row for row in data
                     if len(row) >= 6 and int(row[5]) > 5000]
    return large_packets


def tag_traffic(data):
    """
    מסמן תעבורה כ‑LARGE או NORMAL לפי גודל החבילה.

    ארגומנטים:
    data (list): נתוני תעבורת רשת כרשימה של רשימות

    מחזיר:
    list: רשימת שורות עם תג גודל (SIZE TAG) נוסף כאלמנט השביעי
    """

    tagged_traffic = []
    for row in data:
        if len(row) >= 6:
            tagged_row = row.copy()
            packet_size = int(row[5])
            if packet_size > 5000:
                tagged_row.append('LARGE')
            else:
                tagged_row.append('NORMAL')
            tagged_traffic.append(tagged_row)
    return tagged_traffic
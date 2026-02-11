from config import SENSITIVE_PORTS, INTERNAL_IP_RANGES, LARGE_PACKET_THRESHOLD, NIGHT_START_HOUR, NIGHT_END_HOUR

def extract_hours(data):
    """
    מחלץ שעות מ-timestamp באמצעות map ו-lambda.
    
    ארגומנטים:
    data (list): נתוני תעבורת רשת כרשימת רשימות
    
    מחזיר:
    list: רשימת שעות (0-23) מכל השורות
    """
    return list(map(lambda row: int(row[0].split()[1].split(':')[0]) if len(row) > 0 else 0, data))


def convert_to_kb(sizes):
    """
    ממיר גודל חבילות מבייטים לקילובייט באמצעות map ו-lambda.
    
    ארגומנטים:
    sizes (list): רשימת גדלים בבייטים
    
    מחזיר:
    list: רשימת גדלים בקילובייט
    """
    return list(map(lambda size: round(size / 1024, 2), sizes))


def filter_sensitive_ports_lambda(data):
    """
    מסנן שורות לפי פורט רגיש באמצעות filter ו-lambda.
    
    ארגומנטים:
    data (list): נתוני תעבורת רשת כרשימת רשימות
    
    מחזיר:
    list: רק שורות עם פורט רגיש (22, 23, 3389)
    """
    return list(filter(lambda row: len(row) >= 4 and row[3] in SENSITIVE_PORTS, data))


def filter_night_activity(data):
    """
    מסנן פעילות לילה באמצעות filter ו-lambda.
    
    ארגומנטים:
    data (list): נתוני תעבורת רשת כרשימת רשימות
    
    מחזיר:
    list: רק שורות שהפעילות בהן התרחשה בשעות 00:00-06:00
    """
    return list(filter(lambda row: len(row) > 0 and 
                    NIGHT_START_HOUR <= int(row[0].split()[1].split(':')[0]) < NIGHT_END_HOUR, data))


def create_suspicion_checks():
    """
    יוצר מילון בודקי חשדות עם פונקציות lambda.
    
    מחזיר:
    dict: מילון שם חשד → פונקציית lambda לבדיקה
    """
    return {
        "EXTERNAL_IP": lambda row: len(row) >= 2 and not any(row[1].startswith(prefix) for prefix in INTERNAL_IP_RANGES),
        "SENSITIVE_PORT": lambda row: len(row) >= 4 and row[3] in SENSITIVE_PORTS,
        "LARGE_PACKET": lambda row: len(row) >= 6 and int(row[5]) > LARGE_PACKET_THRESHOLD,
        "NIGHT_ACTIVITY": lambda row: len(row) > 0 and NIGHT_START_HOUR <= int(row[0].split()[1].split(':')[0]) < NIGHT_END_HOUR,
        "FREQUENT_ACCESS": lambda row: len(row) >= 2 and row[1] in ["10.0.0.8", "192.168.1.100"]  # דוגמה ל-IP עם גישה תכופה
    }


def check_row_suspicions(row, suspicion_checks):
    """
    בודק חשדות לשורה ספציפית באמצעות filter.
    
    ארגומנטים:
    row (list): שורה מנתוני הלוג
    suspicion_checks (dict): מילון בודקי חשדות
    
    מחזיר:
    list: רשימת חשדות שהשורה מתאימה להם
    """
    # מסנן רק את הבדיקות שעברו
    passed_checks = filter(lambda check_name: suspicion_checks[check_name](row), suspicion_checks.keys())
    return list(passed_checks)


def process_log(data):
    """
    מעבד את כל הלוג באמצעות map ו-filter.
    
    ארגומנטים:
    data (list): נתוני תעבורת רשת כרשימת רשימות
    
    מחזיר:
    list: רשימת טופלים (שורה, רשימת חשדות) עבור שורות עם חשדות
    """
    suspicion_checks = create_suspicion_checks()
    
    # מפעיל את פונקציית הבדיקה על כל שורה
    all_results = list(map(lambda row: (row, check_row_suspicions(row, suspicion_checks)), data))
    
    # מסנן רק שורות עם לפחות חשד אחד
    suspicious_rows = list(filter(lambda result: len(result[1]) > 0, all_results))
    
    return suspicious_rows


def get_packet_sizes(data):
    """
    מחלץ גדלי חבילות מהנתונים.
    
    ארגומנטים:
    data (list): נתוני תעבורת רשת כרשימת רשימות
    
    מחזיר:
    list: רשימת גדלי חבילות בבייטים
    """
    return list(map(lambda row: int(row[5]) if len(row) >= 6 else 0, data))

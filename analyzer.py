from config import SENSITIVE_PORTS, INTERNAL_IP_RANGES, LARGE_PACKET_THRESHOLD, NIGHT_START_HOUR, NIGHT_END_HOUR

def count_by_ip(data):
    """
    סופר פניות לפי כתובת IP מקור.
    
    ארגומנטים:
    data (list): נתוני תעבורת רשת כרשימת רשימות
    
    מחזיר:
    dict: מילון כתובת IP מקור → מספר פניות
    """
    return {row[1]: data.count(row) for row in data if len(row) >= 2}


def map_port_to_protocol(data):
    """
    ממפה מספר פורט לשם פרוטוקול.
    
    ארגומנטים:
    data (list): נתוני תעבורת רשת כרשימת רשימות
    
    מחזיר:
    dict: מילון מספר פורט → שם פרוטוקול
    """
    return {int(row[3]): row[4] for row in data if len(row) >= 5}


def is_external_ip(ip):
    """
    בודק אם כתובת IP היא חיצונית.
    
    ארגומנטים:
    ip (str): כתובת IP
    
    מחזיר:
    bool: True אם ה-IP חיצוני, False אחרת
    """
    return not any(ip.startswith(range_prefix) for range_prefix in INTERNAL_IP_RANGES)


def is_night_time(timestamp):
    """
    בודק אם הזמן הוא בשעות הלילה (00:00-06:00).
    
    ארגומנטים:
    timestamp (str): תאריך ושעה בפורמט YYYY-MM-DD HH:MM:SS
    
    מחזיר:
    bool: True אם בשעות לילה, False אחרת
    """
    try:
        hour = int(timestamp.split()[1].split(':')[0])
        return NIGHT_START_HOUR <= hour < NIGHT_END_HOUR
    except:
        return False


def detect_suspicions(data):
    """
    מזהה חשדות לכל כתובת IP.
    
    ארגומנטים:
    data (list): נתוני תעבורת רשת כרשימת רשימות
    
    מחזיר:
    dict: מילון כתובת IP → רשימת סוגי חשדות
    """
    suspicions = {}
    
    for row in data:
        if len(row) < 6:
            continue
            
        source_ip = row[1]
        port = row[3]
        size = int(row[5])
        timestamp = row[0]
        
        if source_ip not in suspicions:
            suspicions[source_ip] = set()
        
        # בדיקת IP חיצוני
        if is_external_ip(source_ip):
            suspicions[source_ip].add('EXTERNAL_IP')
        
        # בדיקת פורט רגיש
        if port in SENSITIVE_PORTS:
            suspicions[source_ip].add('SENSITIVE_PORT')
        
        # בדיקת חבילה גדולה
        if size > LARGE_PACKET_THRESHOLD:
            suspicions[source_ip].add('LARGE_PACKET')
        
        # בדיקת פעילות בלילה
        if is_night_time(timestamp):
            suspicions[source_ip].add('NIGHT_ACTIVITY')
    
    # המרת סטים לרשימות
    return {ip: list(suspicions) for ip, suspicions in suspicions.items()}


def filter_multiple_suspicions(suspicions_dict):
    """
    מסנן מילון חשדות ומחזיר רק כתובות IP עם 2+ סוגי חשדות.
    
    ארגומנטים:
    suspicions_dict (dict): מילון חשדות מהפונקציה detect_suspicions
    
    מחזיר:
    dict: מילון מסונן עם כתובות IP שיש להן לפחות 2 חשדות
    """
    return {ip: suspicions for ip, suspicions in suspicions_dict.items() 
            if len(suspicions) >= 2}
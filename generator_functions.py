from config import SENSITIVE_PORTS, INTERNAL_IP_RANGES, LARGE_PACKET_THRESHOLD, NIGHT_START_HOUR, NIGHT_END_HOUR

def read_log_generator(file_path):
    """
    קורא קובץ לוג ומחזיר כל שורה כרשימת שדות עם yield.
    לא טוען את כל הקובץ לזיכרון!
    
    ארגומנטים:
    file_path (str): נתיב לקובץ הלוג
    
    מחזיר:
    generator: מחזיר כל שורה כרשימת שדום
    """
    with open(file_path, 'r', encoding='utf-8') as file:
        for line in file:
            line = line.strip()
            if line:  # דילוג על שורות ריקות
                # פיצול לפי פסיק והסרת רווחים
                row = [field.strip() for field in line.split(',')]
                yield row


def is_external_ip(ip):
    """
    בודק אם כתובת IP היא חיצונית.
    """
    return not any(ip.startswith(prefix) for prefix in INTERNAL_IP_RANGES)


def is_night_time(timestamp):
    """
    בודק אם הזמן הוא בשעות הלילה.
    """
    try:
        hour = int(timestamp.split()[1].split(':')[0])
        return NIGHT_START_HOUR <= hour < NIGHT_END_HOUR
    except:
        return False


def check_suspicions(row):
    """
    בודק חשדות לשורה ספציפית.
    """
    if len(row) < 6:
        return []
    
    suspicions = []
    source_ip = row[1]
    port = row[3]
    size = int(row[5])
    timestamp = row[0]
    
    # בדיקת IP חיצוני
    if is_external_ip(source_ip):
        suspicions.append('EXTERNAL_IP')
    
    # בדיקת פורט רגיש
    if port in SENSITIVE_PORTS:
        suspicions.append('SENSITIVE_PORT')
    
    # בדיקת חבילה גדולה
    if size > LARGE_PACKET_THRESHOLD:
        suspicions.append('LARGE_PACKET')
    
    # בדיקת פעילות בלילה
    if is_night_time(timestamp):
        suspicions.append('NIGHT_ACTIVITY')
    
    return suspicions


def filter_suspicious_generator(lines_generator):
    """
    מסנן רק שורות חשודות עם yield.
    לא טוען את כל השורות לזיכרון!
    
    ארגומנטים:
    lines_generator (generator): generator של שורות מהלוג
    
    מחזיר:
    generator: מחזיר רק שורות עם חשדות
    """
    for row in lines_generator:
        suspicions = check_suspicions(row)
        if suspicions:  # אם יש חשדות
            yield row


def add_suspicion_details_generator(suspicious_generator):
    """
    מוסיף פרטי חשדות לכל שורה חשודה עם yield.
    
    ארגומנטים:
    suspicious_generator (generator): generator של שורות חשודות
    
    מחזיר:
    generator: מחזיר tuple של (שורה, רשימת_חשדות)
    """
    for row in suspicious_generator:
        suspicions = check_suspicions(row)
        yield (row, suspicions)


def count_generator_items(generator):
    """
    סופר פריטים ב-generator בלי לטעון הכל לזיכרון.
    
    ארגומנטים:
    generator: generator לספירה
    
    מחזיר:
    int: מספר הפריטים ב-generator
    """
    count = 0
    for _ in generator:
        count += 1
    return count


def process_large_log(file_path):
    """
    מעבד קובץ לוג ענקי עם שרשרת generators.
    מדגים את היתרון של generators - זיכרון נמוך!
    
    ארגומנטים:
    file_path (str): נתיב לקובץ הלוג
    
    מחזיר:
    tuple: (מספר שורות חשודות, generator של תוצאות מפורטות)
    """
    # שרשרת generators
    lines = read_log_generator(file_path)           # קריאת שורות
    suspicious = filter_suspicious_generator(lines)  # סינון שורות חשודות
    detailed = add_suspicion_details_generator(suspicious)  # הוספת פרטי חשדות
    
    # ספירת שורות חשודות (בלי לצרוך את ה-generator)
    # צריך ליצור generator חדש כי הקודם נצרך
    lines2 = read_log_generator(file_path)
    suspicious2 = filter_suspicious_generator(lines2)
    suspicious_count = count_generator_items(suspicious2)
    
    return suspicious_count, detailed


def get_top_suspicious_ips(detailed_generator, limit=10):
    """
    מחזיר את ה-IPים הכי חשודים מ-generator.
    
    ארגומנטים:
    detailed_generator (generator): generator של (שורה, רשימת_חשדות)
    limit (int): מספר IPים להחזיר
    
    מחזיר:
    list: רשימת (IP, רשימת_חשדות, מספר_חשדות)
    """
    ip_suspicions = {}
    
    for row, suspicions in detailed_generator:
        ip = row[1]
        if ip not in ip_suspicions:
            ip_suspicions[ip] = set()
        ip_suspicions[ip].update(suspicions)
    
    # מיון לפי מספר חשדות
    sorted_ips = sorted(ip_suspicions.items(), 
                     key=lambda x: len(x[1]), reverse=True)
    
    return [(ip, list(suspicions), len(suspicions)) 
            for ip, suspicions in sorted_ips[:limit]]

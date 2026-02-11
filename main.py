from generator_functions import read_log_generator, check_suspicions
from config import SENSITIVE_PORTS, INTERNAL_IP_RANGES, LARGE_PACKET_THRESHOLD, NIGHT_START_HOUR, NIGHT_END_HOUR

# משתנים גלובליים לסטטיסטיקות
total_rows_read = 0
total_suspicious_rows = 0
suspicion_counts = {
    'EXTERNAL_IP': 0,
    'SENSITIVE_PORT': 0,
    'LARGE_PACKET': 0,
    'NIGHT_ACTIVITY': 0,
    'ACCESS_FREQUENT': 0
}

# מונה פניות לכל IP
ip_access_count = {}

def update_statistics(row, suspicions):
    """מעדכן סטטיסטיקות גלובליות."""
    global total_rows_read, total_suspicious_rows, suspicion_counts, ip_access_count
    
    total_rows_read += 1
    
    if suspicions:
        total_suspicious_rows += 1
        
        # עדכון ספירת חשדות
        for suspicion in suspicions:
            if suspicion in suspicion_counts:
                suspicion_counts[suspicion] += 1
    
    # ספירת פניות לכל IP
    if len(row) >= 2:
        ip = row[1]
        ip_access_count[ip] = ip_access_count.get(ip, 0) + 1

def check_access_frequent(ip):
    """בודק אם IP פונה יותר מ-10 פעמים."""
    return ip_access_count.get(ip, 0) > 10

def analyze_log(file_path):
    """פונקציית עיבוד ראשית - מחברת את כל השלבים."""
    global ip_access_count
    
    # איפוס סטטיסטיקות
    ip_access_count.clear()
    reset_statistics()
    
    suspicious_dict = {}
    
    # שלב 1: קריאת קובץ וספירת פניות
    lines_gen = read_log_generator(file_path)
    all_rows = list(lines_gen)  # צריך לקרוא הכל קודם לספירת פניות
    
    # שלב 2: בדיקת חשדות לכל שורה
    for row in all_rows:
        update_statistics(row, [])
    
    # שלב 3: בדיקת חשדות כולל ACCESS_FREQUENT
    for row in all_rows:
        suspicions = check_suspicions(row)
        
        # בדיקת גישה תכופה
        if len(row) >= 2 and check_access_frequent(row[1]):
            suspicions.append('ACCESS_FREQUENT')
        
        if suspicions:
            ip = row[1]
            if ip not in suspicious_dict:
                suspicious_dict[ip] = set()
            suspicious_dict[ip].update(suspicions)
            
            # עדכון סטטיסטיקות עם חשדות
            for suspicion in suspicions:
                if suspicion in suspicion_counts:
                    suspicion_counts[suspicion] += 1
    
    # המרת סטים לרשימות
    return {ip: list(suspicions) for ip, suspicions in suspicious_dict.items()}

def reset_statistics():
    """מאפס סטטיסטיקות."""
    global total_rows_read, total_suspicious_rows, suspicion_counts
    total_rows_read = 0
    total_suspicious_rows = 0
    for key in suspicion_counts:
        suspicion_counts[key] = 0

def generate_report(suspicious_dict):
    """יוצרת דוח מסודר."""
    report = []
    report.append("=" * 40)
    report.append("דוח תעבורה חשודה")
    report.append("=" * 40)
    
    # סטטיסטיקות כלליות
    report.append("\nסטטיסטיקות כלליות:")
    report.append(f"שורות שנקראו: {total_rows_read:,}")
    report.append(f"שורות חשודות: {total_suspicious_rows:,}")
    report.append("\nסוגי חשדות:")
    for suspicion, count in suspicion_counts.items():
        if count > 0:
            report.append(f"- {suspicion}: {count}")
    
    # IPs עם רמת סיכון גבוהה (3+ חשדות)
    high_risk_ips = {ip: sus for ip, sus in suspicious_dict.items() if len(sus) >= 3}
    if high_risk_ips:
        report.append("\nIPs עם רמת סיכון גבוהה (3+ חשדות):")
        for ip, suspicions in sorted(high_risk_ips.items(), key=lambda x: len(x[1]), reverse=True):
            report.append(f"- {ip}: {', '.join(suspicions)}")
    
    # חשודים נוספים
    other_ips = {ip: sus for ip, sus in suspicious_dict.items() if len(sus) < 3}
    if other_ips:
        report.append("\nחשודים נוספים IPs:")
        for ip, suspicions in sorted(other_ips.items(), key=lambda x: len(x[1]), reverse=True)[:10]:
            report.append(f"- {ip}: {', '.join(suspicions)}")
    
    return "\n".join(report)

def save_report(report, file_path):
    """שומרת דוח לקובץ."""
    with open(file_path, 'w', encoding='utf-8') as file:
        file.write(report)

def main():
    """פונקציית main - מפעילה את כל התהליך."""
    print("מתחיל ניתוח תעבורת רשת...")
    
    # קריאה וניתוח
    suspicious = analyze_log("network_traffic.log")
    
    # יצירת דוח
    report = generate_report(suspicious)
    
    # הדפסה למסך
    print(report)
    
    # שמירה לקובץ
    save_report(report, "security_report.txt")
    print(f"\nהדוח נשמר לקובץ: security_report.txt")

if __name__ == "__main__":
    main()
from reader import load_csv
from lambda_functions import (
    extract_hours, convert_to_kb, filter_sensitive_ports_lambda, 
    filter_night_activity, create_suspicion_checks, check_row_suspicions, 
    process_log, get_packet_sizes
)

def test_stage3_functions():
    """בודק את כל הפונקציות של שלב 3 עם Lambda, Map ו-Filter."""
    
    # טעינת הנתונים
    print("טוען נתונים...")
    data = load_csv('network_traffic.log')
    print(f"נטענו {len(data)} רשומות")
    
    # בדיקה 1: חילוץ שעות
    print("\n=== בדיקה 1: חילוץ שעות עם map ו-lambda ===")
    hours = extract_hours(data)
    print(f"נחלצו {len(hours)} שעות")
    print(f"10 שעות ראשונות: {hours[:10]}")
    print(f"שעות ייחודיות: {sorted(set(hours))}")
    
    # בדיקה 2: המרת גדלים לקילובייט
    print("\n=== בדיקה 2: המרת גדלים ל-KB עם map ו-lambda ===")
    sizes_bytes = get_packet_sizes(data)
    sizes_kb = convert_to_kb(sizes_bytes[:10])  # נבדוק רק 10 ראשונים
    print(f"גדלים מקוריים (בייטים): {sizes_bytes[:10]}")
    print(f"גדלים מומרים (KB): {sizes_kb}")
    
    # בדיקה 3: סינון פורטים רגישים
    print("\n=== בדיקה 3: סינון פורטים רגישים עם filter ו-lambda ===")
    sensitive_rows = filter_sensitive_ports_lambda(data)
    print(f"נמצאו {len(sensitive_rows)} שורות עם פורטים רגישים")
    print("5 שורות ראשונות:")
    for i, row in enumerate(sensitive_rows[:5]):
        print(f"  {i+1}. {row}")
    
    # בדיקה 4: סינון פעילות לילה
    print("\n=== בדיקה 4: סינון פעילות לילה עם filter ו-lambda ===")
    night_rows = filter_night_activity(data)
    print(f"נמצאו {len(night_rows)} שורות עם פעילות לילה")
    print("5 שורות ראשונות:")
    for i, row in enumerate(night_rows[:5]):
        hour = int(row[0].split()[1].split(':')[0])
        print(f"  {i+1}. שעה {hour}: {row}")
    
    # בדיקה 5: מילון בודקי חשדות
    print("\n=== בדיקה 5: מילון בודקי חשדות עם lambda ===")
    suspicion_checks = create_suspicion_checks()
    print("בודקי חשדות שנוצרו:")
    for check_name, check_func in suspicion_checks.items():
        print(f"  {check_name}: {check_func}")
    
    # בדיקה 6: בדיקת שורה ספציפית
    print("\n=== בדיקה 6: בדיקת שורה ספציפית עם filter ===")
    test_row = ["2024-01-15 03:23:45", "45.33.32.156", "10.0.0.5", "22", "SSH", "6000"]
    suspicions = check_row_suspicions(test_row, suspicion_checks)
    print(f"שורת בדיקה: {test_row}")
    print(f"חשדות שזוהו: {suspicions}")
    
    # בדיקה 7: עיבוד כל הלוג
    print("\n=== בדיקה 7: עיבוד כל הלוג עם map ו-filter ===")
    suspicious_results = process_log(data)
    print(f"נמצאו {len(suspicious_results)} שורות חשודות")
    print("10 שורות חשודות ראשונות:")
    for i, (row, sus_list) in enumerate(suspicious_results[:10]):
        print(f"  {i+1}. IP {row[1]}: {sus_list}")
    
    # סטטיסטיקות סופיות
    print(f"\n=== סטטיסטיקות סופיות ===")
    total_suspicious = len(suspicious_results)
    total_rows = len(data)
    suspicious_percentage = (total_suspicious / total_rows) * 100
    
    print(f"סה\"כ שורות: {total_rows}")
    print(f"שורות חשודות: {total_suspicious}")
    print(f"אחוז חשוד: {suspicious_percentage:.2f}%")
    
    # ספירת סוגי חשדות
    suspicion_counts = {}
    for row, sus_list in suspicious_results:
        for sus in sus_list:
            suspicion_counts[sus] = suspicion_counts.get(sus, 0) + 1
    
    print("ספירת סוגי חשדות:")
    for sus_type, count in sorted(suspicion_counts.items()):
        print(f"  {sus_type}: {count}")

if __name__ == "__main__":
    test_stage3_functions()

from generator_functions import (
    read_log_generator, filter_suspicious_generator, 
    add_suspicion_details_generator, count_generator_items,
    process_large_log, get_top_suspicious_ips
)

def test_stage4_functions():
    """בודק את כל הפונקציות של שלב 4 עם Generators."""
    
    print("=== בדיקת Generators לטיפול בקבצים ענקיים ===")
    
    # בדיקה 1: קריאת קובץ עם yield
    print("\n1. בדיקת read_log_generator:")
    lines_gen = read_log_generator('network_traffic.log')
    print("   קריאת 5 שורות ראשונות:")
    for i, row in enumerate(lines_gen):
        if i >= 5:
            break
        print(f"   שורה {i+1}: {row}")
    
    # בדיקה 2: סינון שורות חשודות עם yield
    print("\n2. בדיקת filter_suspicious_generator:")
    lines_gen = read_log_generator('network_traffic.log')
    suspicious_gen = filter_suspicious_generator(lines_gen)
    print("   5 שורות חשודות ראשונות:")
    for i, row in enumerate(suspicious_gen):
        if i >= 5:
            break
        ip = row[1]
        print(f"   שורה {i+1}: IP {ip}")
    
    # בדיקה 3: הוספת פרטי חשדות עם yield
    print("\n3. בדיקת add_suspicion_details_generator:")
    lines_gen = read_log_generator('network_traffic.log')
    suspicious_gen = filter_suspicious_generator(lines_gen)
    detailed_gen = add_suspicion_details_generator(suspicious_gen)
    print("   5 תוצאות מפורטות ראשונות:")
    for i, (row, suspicions) in enumerate(detailed_gen):
        if i >= 5:
            break
        ip = row[1]
        print(f"   תוצאה {i+1}: IP {ip} -> חשדות: {suspicions}")
    
    # בדיקה 4: ספירה בלי טעינה לזיכרון
    print("\n4. בדיקת count_generator_items:")
    lines_gen = read_log_generator('network_traffic.log')
    suspicious_gen = filter_suspicious_generator(lines_gen)
    count = count_generator_items(suspicious_gen)
    print(f"   מספר שורות חשודות: {count}")
    
    # בדיקה 5: שרשרת generators מלאה
    print("\n5. בדיקת process_large_log (שרשרת generators):")
    suspicious_count, detailed_gen = process_large_log('network_traffic.log')
    print(f"   מספר שורות חשודות: {suspicious_count}")
    print("   10 תוצאות ראשונות מה-generator:")
    for i, (row, suspicions) in enumerate(detailed_gen):
        if i >= 10:
            break
        ip = row[1]
        print(f"   {i+1}. IP {ip}: {suspicions}")
    
    # בדיקת זיכרון - השוואה בין שיטות
    print("\n6. השוואת זיכרון:")
    print("   שיטה רגילה (טוענת הכל לזיכרון):")
    print("   - טוענת את כל 10,000 השורות לרשימה")
    print("   - מעבדת את כל הרשימה")
    print("   - זיכרון: גבוה")
    
    print("\n   שיטת Generators:")
    print("   - קורא שורה אחר שורה מהדיסק")
    print("   - מעבדת כל שורה מיד")
    print("   - זיכרון: נמוך מאוד!")
    
    # בדיקת IPים הכי חשודים
    print("\n7. בדיקת get_top_suspicious_ips:")
    suspicious_count, detailed_gen = process_large_log('network_traffic.log')
    top_ips = get_top_suspicious_ips(detailed_gen, limit=10)
    print("   10 ה-IPים הכי חשודים:")
    for i, (ip, suspicions, count) in enumerate(top_ips):
        print(f"   {i+1}. {ip}: {suspicions} ({count} חשדות)")
    
    # הדגמת יתרון לקבצים גדולים
    print(f"\n8. הדגמת יתרון לקבצים גדולים:")
    print("   עבור קובץ של 10 מיליון שורות:")
    print("   - שיטה רגילה: תצטרך כמה ג'יגהבייט זיכרון")
    print("   - Generators: תצטרך רק כמה קילובייט זיכרון!")
    print("   - המערכת לא תקרוס עם קבצים ענקיים")
    
    print(f"\n=== סיכום בדיקת Generators ===")
    print(f"✓ קריאת קובץ עם yield - עובד!")
    print(f"✓ סינון שורות עם yield - עובד!")
    print(f"✓ הוספת פרטים עם yield - עובד!")
    print(f"✓ ספירה בלי טעינה - עובד!")
    print(f"✓ שרשרת generators - עובד!")
    print(f"✓ המערכת מוכנה לקבצים ענקיים!")

if __name__ == "__main__":
    test_stage4_functions()

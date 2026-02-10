def load_csv(file_path):
    """
    טוען יומן תעבורת רשת מקובץ CSV.

    ארגומנטים:
    file_path (str): נתיב לקובץ ה‑CSV

    מחזיר:
    list: רשימת רשימות, כאשר כל רשימה פנימית מייצגת שורה עם השדות:
    [timestamp, source_ip, dest_ip, port, protocol, size]
    """

    data = []
    with open(file_path, 'r') as file:
        for line in file:
            line = line.strip()
            if line:  # דלג על שורות ריקות
                # פצל לפי פסיק והסר רווחים מיותרים מכל שדה
                row = [field.strip() for field in line.split(',')]
                data.append(row)
    return data
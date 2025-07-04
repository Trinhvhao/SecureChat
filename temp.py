import sqlite3

# Kết nối tới đúng file database
conn = sqlite3.connect('instance/chat.db')
cursor = conn.cursor()

# Kiểm tra bảng 'users' có tồn tại không (tuỳ chọn để debug)
cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='users'")
if cursor.fetchone() is None:
    print("❌ Không tìm thấy bảng 'users' trong chat.db")
else:
    # Cập nhật tên
    cursor.execute("""
        UPDATE users
        SET name = ?
        WHERE gmail = ?
    """, ('Đức Huy', 'trinhhaommo142@gmail.com'))

    conn.commit()
    print("✅ Đã cập nhật name thành 'Đức Huy' cho gmail 'trinhhaommo142@gmail.com'")

conn.close()

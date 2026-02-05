import streamlit as st
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import os

st.set_page_config(page_title="File Encryption Tool", page_icon="🔐")
st.title("🔐 File Encryption Tool")
st.markdown("**أداة آمنة لتشفير وفك تشفير الملفات باستخدام Fernet (AES-based).**")
st.markdown("**by anis zidane**")  

# دالة توليد مفتاح من كلمة مرور
def generate_key(password: str, salt: bytes = None):
    if salt is None:
        salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return key, salt

# دالة تشفير الملف
def encrypt_file(file_data, password):
    key, salt = generate_key(password)
    fernet = Fernet(key)
    encrypted = fernet.encrypt(file_data)
    return encrypted, salt

# دالة فك تشفير الملف
def decrypt_file(encrypted_data, password, salt):
    key, _ = generate_key(password, salt)
    fernet = Fernet(key)
    try:
        decrypted = fernet.decrypt(encrypted_data)
        return decrypted
    except Exception as e:
        st.error(f"خطأ في فك التشفير: {e}. تحقق من كلمة المرور.")
        return None

# واجهة المستخدم
tab1, tab2 = st.tabs(["تشفير ملف", "فك تشفير ملف"])

with tab1:
    st.header("تشفير ملف")
    uploaded_file = st.file_uploader("اختر ملفاً للتشفير", type=None)
    password = st.text_input("أدخل كلمة مرور قوية (8 أحرف على الأقل)", type="password")
    if st.button("شفر الملف"):
        if uploaded_file and password and len(password) >= 8:
            file_data = uploaded_file.read()
            encrypted_data, salt = encrypt_file(file_data, password)
            # حفظ الـ salt مع البيانات المشفرة
            combined = salt + encrypted_data
            st.download_button(
                label="تنزيل الملف المشفر",
                data=combined,
                file_name=f"{uploaded_file.name}.encrypted",
                mime="application/octet-stream"
            )
            st.success("تم التشفير بنجاح! احفظ كلمة المرور.")
        else:
            st.error("يرجى رفع ملف وإدخال كلمة مرور قوية.")

with tab2:
    st.header("فك تشفير ملف")
    uploaded_encrypted = st.file_uploader("اختر ملفاً مشفراً", type=None)
    password_decrypt = st.text_input("أدخل كلمة المرور", type="password")
    if st.button("فك تشفير الملف"):
        if uploaded_encrypted and password_decrypt:
            combined_data = uploaded_encrypted.read()
            if len(combined_data) < 16:
                st.error("الملف غير صالح.")
                return
            salt = combined_data[:16]
            encrypted_data = combined_data[16:]
            decrypted_data = decrypt_file(encrypted_data, password_decrypt, salt)
            if decrypted_data:
                original_name = uploaded_encrypted.name.replace(".encrypted", "")
                st.download_button(
                    label="تنزيل الملف المفكك",
                    data=decrypted_data,
                    file_name=original_name,
                    mime="application/octet-stream"
                )
                st.success("تم فك التشفير بنجاح!")
        else:
            st.error("يرجى رفع ملف مشفر وإدخال كلمة المرور.")

st.markdown("---")
st.markdown("**نصائح الأمان:**")
st.markdown("- استخدم كلمات مرور قوية (مزيج من أحرف، أرقام، رموز).")
st.markdown("- لا تنس كلمة المرور – لا يمكن استرجاعها.")
st.markdown("thank you")

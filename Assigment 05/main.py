import streamlit as st
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from base64 import urlsafe_b64encode
import os
import sys
print(sys.path)
try:
    from cryptography.fernet import Fernet
    print("Fernet is available!")
except ImportError as e:
    print("Fernet not found:", e)

# Page config
st.set_page_config(page_title="🔐 SecureVault", layout="centered")

# ---------------------- Setup ----------------------
# Function: Derive encryption key from password
def get_fernet(password: str, salt: bytes) -> Fernet:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100_000,
    )
    key = urlsafe_b64encode(kdf.derive(password.encode()))
    return Fernet(key)

# ---------------------- Session State Setup ----------------------
if "user_data" not in st.session_state:
    st.session_state.user_data = {}  # {username: (password, vault)}
if "salt" not in st.session_state:
    st.session_state.salt = os.urandom(16)
if "current_user" not in st.session_state:
    st.session_state.current_user = None

# ---------------------- Sidebar: Create Username and Password ----------------------
if st.session_state.current_user is None:
    st.sidebar.title("🔐 Create or Login to Your Account")

    # Create a new username
    username = st.sidebar.text_input("Username", value="", max_chars=20)

    # Create a password
    password_input = st.sidebar.text_input("Enter your password", type="password")

    # Login button to validate user
    if st.sidebar.button("Login"):
        if username in st.session_state.user_data:
            stored_password, _ = st.session_state.user_data[username]
            if password_input == stored_password:
                st.session_state.current_user = username
                st.sidebar.success(f"✅ Welcome back, {username}!")
            else:
                st.sidebar.error("❌ Incorrect password!")
        else:
            st.sidebar.error("❌ Username not found!")

    # Option to create new account
    if username and password_input and username not in st.session_state.user_data:
        if st.sidebar.button("Create Account"):
            st.session_state.user_data[username] = (password_input, {})  # (password, vault)
            st.session_state.current_user = username
            st.sidebar.success("✅ Account created successfully!")

elif st.session_state.current_user:
    # Logged In State
    # Get user data and set up encryption
    user_password, user_vault = st.session_state.user_data[st.session_state.current_user]
    fernet = get_fernet(user_password, st.session_state.salt)

    st.title(f"🛡️ SecureVault - {st.session_state.current_user}'s Vault")
    
    # Logout Button
    if st.sidebar.button("Logout"):
        st.session_state.current_user = None
        st.session_state.user_data = {}
        st.session_state.salt = os.urandom(16)  # Reset the salt to avoid session hijacking
        st.sidebar.success("✅ You have logged out successfully.")
        
    # ---------------------- Store Secret ----------------------
    menu = st.radio("Choose Action", ["➕ Store Secret", "🔍 View Secret", "❌ Delete Secret"])

    if menu == "➕ Store Secret":
        st.subheader("Store a New Secret")
        label = st.text_input("Secret Name (e.g., 'Gmail Password')")
        secret_value = st.text_area("Secret Value")

        if st.button("🔐 Encrypt and Store"):
            if not label or not secret_value:
                st.warning("Label and value cannot be empty.")
            elif label in user_vault:
                st.warning("A secret with this name already exists.")
            else:
                encrypted = fernet.encrypt(secret_value.encode())
                user_vault[label] = encrypted
                st.session_state.user_data[st.session_state.current_user] = (user_password, user_vault)
                st.success(f"✅ Secret '{label}' stored securely!")

    # ---------------------- View Secret ----------------------
    elif menu == "🔍 View Secret":
        st.subheader("View Your Secret")
        if not user_vault:
            st.info("🔐 No secrets stored yet.")
        else:
            label = st.selectbox("Choose a Secret to View", list(user_vault.keys()))
            if st.button("🔓 Decrypt Secret"):
                try:
                    encrypted = user_vault[label]
                    decrypted = fernet.decrypt(encrypted).decode()
                    st.success(f"🔐 Decrypted Secret for '{label}':")
                    st.code(decrypted)
                except Exception:
                    st.error("❌ Invalid password or corrupted secret.")

    # ---------------------- Delete Secret ----------------------
    elif menu == "❌ Delete Secret":
        st.subheader("Delete a Stored Secret")
        if not user_vault:
            st.info("🔐 No secrets to delete.")
        else:
            label = st.selectbox("Choose a Secret to Delete", list(user_vault.keys()))
            if st.button("🗑️ Delete Secret"):
                del user_vault[label]
                st.session_state.user_data[st.session_state.current_user] = (user_password, user_vault)
                st.success(f"✅ Secret '{label}' deleted.")

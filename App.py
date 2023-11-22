import streamlit as st
import base64

def decrypt(message, password):
    if password == "1234":
        base64_bytes = base64.b64decode(message)
        decrypted_message = base64_bytes.decode("ascii")
        return decrypted_message
    else:
        return "Invalid Password"

def encrypt(message, password):
    if password == "1234":
        base64_bytes = base64.b64encode(message.encode("ascii"))
        encrypted_message = base64_bytes.decode("ascii")
        return encrypted_message
    else:
        return "Invalid Password"

def main():
    st.title("HowsApp")

    text_input = st.text_area("Enter text for encryption and decryption:")
    password = st.text_input("Enter secret key for encryption and decryption:", type="password")

    if st.button("ENCRYPT"):
        encrypted_message = encrypt(text_input, password)
        st.text_area("Encrypted Text:", value=encrypted_message)

    if st.button("DECRYPT"):
        decrypted_message = decrypt(text_input, password)
        st.text_area("Decrypted Text:", value=decrypted_message)

if __name__ == "__main__":
    main()



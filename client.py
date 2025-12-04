import streamlit as st
import requests
import pandas as pd

API = "http://127.0.0.1:8000"

# ==========================================================
#   API WRAPPER (Token-based communication)
# ==========================================================
def api_get(path):
    return requests.get(API + path,
        headers={"Authorization": f"Bearer {st.session_state['access']}"})

def api_post(path, data=None):
    return requests.post(API + path,
        json=data, headers={"Authorization": f"Bearer {st.session_state['access']}"})

def api_delete(path, data=None):
    return requests.delete(API + path, json=data, headers={"Authorization": f"Bearer {st.session_state['access']}"})

# ==========================================================
#   MAIN GAME UI
# ==========================================================
def show_app():
    st.title(f"🎯 Welcome {st.session_state['user']} to the Game!")

    # ===== Khởi tạo session nếu chưa có =====
    if "last_guess" not in st.session_state:
        st.session_state.last_guess = None
    if "last_system" not in st.session_state:
        st.session_state.last_system = None
    if "last_result_text" not in st.session_state:
        st.session_state.last_result_text = None

    # Load user stats
    r = api_get("/user")
    if r.status_code == 200:
        st.session_state['scores'] = r.json()["scores"]
        st.session_state['turns'] = r.json()["turns"]

    col1, col2 = st.columns([3,1])

    # ================= LEFT SIDE ====================
    with col1:
        st.subheader("🎮 Play")
        st.info(f"🏆 Score: **{st.session_state['scores']}** | 🔄 Turns: **{st.session_state['turns']}**")

        # ===== LAST TURN DISPLAY =====
        st.markdown("### ⏪ Last Turn")
        if st.session_state.last_guess is not None:
            st.write(f"👤 Your guess: **{st.session_state.last_guess}**")
            st.write(f"🖥️ System number: **{st.session_state.last_system}**")
            result = st.session_state.last_result_text

            if "Correct" in result:
                color = "#4CAF50"     # Green - correct
            else:
                color = "#c81e1e"     # Red - incorrect

            # Result line with custom background
            st.markdown(
                f"""
                <div style='background:{color}; padding:8px 12px; 
                            border-radius:6px; color:white; font-size:17px;'>
                    📊 Result: <b>{result}</b>
                </div>
                """,
                unsafe_allow_html=True
            )
        else:
            st.write("No turns played yet.")

        st.markdown("---")

        # ============= PLAY AREA =============
        guess = st.number_input("Pick a number (1-5)", 1, 5, 1)
        play = st.button("Guess")

        if play:
            if st.session_state['turns'] <= 0:
                st.error("Turns are over! Buy more turns to continue playing.")
            else:
                r = api_post("/guess", {"guess": guess})
                if r.status_code == 200:
                    data = r.json()

                    st.session_state.last_guess = guess
                    st.session_state.last_system = data["system"]
                    st.session_state.last_result_text = (
                        "✅ Correct!" if guess == data["system"] else "❌ Incorrect!"
                    )

                    st.success(f"System: {data['system']} | Score: {data['scores']} | Turns: {data['turns']}")
                    st.rerun()
                else:
                    st.error(r.json()['detail'])

        st.markdown("### 💰 Buy more turns")
        if st.button("Get 5 turns"):
            r = api_post("/buy-turns")
            if r.status_code == 200:
                st.success(f"New turns: {r.json()['turns']}")
                st.rerun()

        st.markdown("---")
        st.subheader("⚙ Account")
        if st.button("Logout"):
            for k in list(st.session_state): del st.session_state[k]
            st.rerun()

        delete = st.checkbox("Delete Account ❗")
        if delete:
            pw = st.text_input("Confirm Password", type="password")
            if st.button("Confirm Delete"):
                r = api_delete("/delete", {"password": pw})
                if r.status_code == 200:
                    st.success("Account deleted.")
                    for k in list(st.session_state): del st.session_state[k]
                    st.rerun()
                else:
                    st.error(r.json()['detail'])

    # ================= RIGHT SIDE — LEADERBOARD ====================
    with col2:
        st.subheader("🥇 Leaderboard")
        r = requests.get(API+"/leaderboard")
        if r.status_code == 200:
            df = pd.DataFrame(r.json())
            df.index+=1
            st.table(df)
        else:
            st.error("Cannot load ranking")

# ==========================================================
#   LOGIN & REGISTER SCREEN
# ==========================================================
if 'user' not in st.session_state:
    st.session_state['user']=None

if st.session_state['user'] is None:
    tab_login, tab_reg = st.tabs(["Login","Register"])

    with tab_login:
        st.subheader("🔐 Login")
        u = st.text_input("Username")
        p = st.text_input("Password",type="password")
        if st.button("Login"):
            r = requests.post(API+"/login",json={"username":u,"password":p})
            if r.status_code == 200:
                st.session_state['user']=u
                st.session_state['access']=r.json()["access_token"]
                st.session_state['refresh']=r.json()["refresh_token"]
                st.success("Login OK"); st.rerun()
            else:
                st.error(r.json()['detail'])

    with tab_reg:
        st.subheader("📝 Register now")
        u = st.text_input("Username",key="reg_u")
        e = st.text_input("Email",key="reg_e")
        p = st.text_input("Password",type="password",key="reg_p")
        if st.button("Register"):
            r = requests.post(API+"/register",json={"username":u,"email":e,"password":p})
            if r.status_code == 200:
                st.success("Registration successful. Log in to play.")
            else:
                st.error(r.json()['detail'])
else:
    show_app()

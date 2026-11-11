# ============================================================
#  Smart Password Security Analyzer
#  -----------------------------------------------------------
#  Ye Streamlit app password ki strength locally check karti hai.
#  Password kabhi store, print ya transmit nahi hota - pura
#  analysis sirf user ke computer par hota hai.
# ============================================================

import math
import re

import pandas as pd
import streamlit as st


# ===========================================================
#  PART 1 - UI (design) ke functions
#  Ye sirf dikhne ke liye hain, isme password ka data nahi jaata
# ===========================================================

def set_cyber_theme():
    """Dark cyber-security wala theme set karne ke liye CSS.

    Ye sirf look ke liye hai - isme user ka password kahin nahi jaata.
    """
    cyber_css = """
    <style>
    /* App ka background dark rakhte hain taaki cyber look aaye */
    .stApp {
        background-color: #070b12;
        color: #d7e3ea;
    }

    /* Title aur headings ko neon green color dete hain */
    h1, h2, h3 {
        color: #00e5c0;
        font-family: "Segoe UI", sans-serif;
    }

    /* Sidebar ka background thoda alag rakha hai */
    section[data-testid="stSidebar"] {
        background-color: #0b1220;
    }

    /* Password input box ko highlighted look diya hai */
    div[data-testid="stTextInput"] input {
        background-color: #0e1626;
        border: 1px solid #16c79a;
        color: #ffffff;
        font-size: 18px;
        letter-spacing: 1px;
    }

    /* Metric cards (length, entropy etc.) ke liye box */
    div[data-testid="stMetric"] {
        background-color: #0e1626;
        border: 1px solid #1b3a2f;
        border-radius: 12px;
        padding: 14px;
    }

    /* Strength meter ki bar par gradient color */
    div[data-testid="stProgress"] > div > div > div > div {
        background: linear-gradient(90deg, #ff4d4d, #ffb300, #00e676);
    }

    /* Character type cards (uppercase / lowercase wale) */
    .type-card {
        border-radius: 12px;
        padding: 14px;
        text-align: center;
        font-weight: 600;
        margin: 6px 0;
        font-size: 15px;
    }
    .type-card.yes {
        background-color: #062b21;
        border: 1px solid #00e676;
        color: #a9ffd8;
    }
    .type-card.no {
        background-color: #2b0606;
        border: 1px solid #ff5252;
        color: #ffc4c4;
    }

    /* Weak pattern ki har line ke liye chhota box */
    .issue-box {
        background-color: #241114;
        border-left: 4px solid #ff5252;
        padding: 8px 12px;
        border-radius: 6px;
        margin: 4px 0;
        color: #ffd7d7;
    }
    </style>
    """
    st.markdown(cyber_css, unsafe_allow_html=True)


def show_sidebar():
    """Left side me about + privacy note + tips dikhata hai."""
    with st.sidebar:
        st.markdown("## 🛡️ About")
        st.write(
            "Ye ek beginner-level project hai jo password ki strength "
            "check karta hai using simple rules + entropy formula."
        )
        st.markdown("### 🔒 Privacy Pledge")
        st.info(
            "Aapka password **kahin save, print ya send nahi hota**. "
            "Saara analysis isi browser session me hota hai."
        )
        st.markdown("### 💪 Strong Password Tips")
        st.write("1. Kam se kam **12-16 characters** rakhein.")
        st.write("2. Upper + lower + number + symbol sab mix karein.")
        st.write("3. Dictionary words aur 1234 / abcd sequence avoid karein.")
        st.write("4. Har site ka alag password rakhein.")
        st.caption("Version 1.0 | Made with Streamlit")


def show_page_header():
    """Top ka title aur short intro dikhata hai."""
    st.markdown(
        "<h1>🔐 Smart Password Security Analyzer</h1>",
        unsafe_allow_html=True,
    )
    st.markdown(
        "Apna password type karein aur **turant security report** paaiye. "
        "Analysis **100% aapke computer par** hota hai - "
        "password kabhi save ya transmit nahi hota."
    )


def show_strength_meter(score, strength_label):
    """Colored progress bar wala strength meter dikhata hai.

    Weak = laal, Medium = peela, Strong = hara.
    """
    color_map = {"Weak": "#ff5252", "Medium": "#ffb300", "Strong": "#00e676"}
    meter_color = color_map.get(strength_label, "#ffffff")

    meter_html = f"""
    <div style="background:#0e1626; border:1px solid #1b3a2f; border-radius:10px;
                height:26px; overflow:hidden;">
        <div style="width:{score}%; height:100%; background:{meter_color};
                    transition:width 0.4s ease;"></div>
    </div>
    <p style="text-align:center; color:{meter_color}; font-weight:bold;
              font-size:17px; margin-top:8px;">
        {strength_label} &nbsp;|&nbsp; Score: {score} / 100
    </p>
    """
    st.markdown(meter_html, unsafe_allow_html=True)
    # Neeche normal progress bar bhi dikhate hain (Streamlit ka built-in)
    st.progress(score)


def show_metric_row(result):
    """Dashboard ke 4 important numbers dikhata hai."""
    col1, col2, col3, col4 = st.columns(4)
    col1.metric("📏 Length", f"{result['length']} chars")
    col2.metric("🧮 Entropy", f"{result['entropy']} bits")
    col3.metric("⏱️ Crack Time (approx)", result["crack_time"])
    col4.metric("🎯 Score", f"{result['score']} / 100")


def show_character_type_cards(character_types):
    """Uppercase / lowercase / number / symbol ka status cards me dikhata hai."""
    card_details = [
        ("Uppercase A-Z", "uppercase"),
        ("Lowercase a-z", "lowercase"),
        ("Numbers 0-9", "numbers"),
        ("Special !@#", "special"),
    ]
    columns = st.columns(4)
    for column, (display_name, type_key) in zip(columns, card_details):
        if character_types[type_key]:
            column.markdown(
                f"<div class='type-card yes'>✅ {display_name}<br/>MIL GAYA</div>",
                unsafe_allow_html=True,
            )
        else:
            column.markdown(
                f"<div class='type-card no'>❌ {display_name}<br/>NAHI HAI</div>",
                unsafe_allow_html=True,
            )


def show_pattern_issues(pattern_issues):
    """Jo bhi weak patterns mile unhe red boxes me dikhata hai."""
    if not pattern_issues:
        st.success("✅ Koi common password ya weak pattern nahi mila. Shandaar!")
    else:
        st.warning(f"⚠️ {len(pattern_issues)} weak pattern mile:")
        for issue_message, _penalty in pattern_issues:
            st.markdown(
                f"<div class='issue-box'>🔸 {issue_message}</div>",
                unsafe_allow_html=True,
            )


def show_suggestions(suggestions):
    """Real-time security suggestions list dikhata hai."""
    if len(suggestions) == 1 and suggestions[0].startswith("Bahut badhiya"):
        st.success("💡 " + suggestions[0])
    else:
        st.info("💡 Suggestion(s):")
        for suggestion in suggestions:
            st.write("• " + suggestion)


def show_final_report(report_table):
    """Final report ko pandas table ki form me dikhata hai."""
    st.dataframe(report_table, hide_index=True)
    st.caption(
        "Note: Report me sirf analysis numbers hain - "
        "password ki value kabhi table me store nahi hoti."
    )


# ===========================================================
#  PART 2 - Validation (input check) function
# ===========================================================

def validate_password_input(password, max_length=64):
    """Password field ki basic validation karta hai.

    Returns: (is_valid, error_message)
    - Khali input ya bohot lambi input par error dete hain.
    """
    if password is None:
        return False, "Password field khali hai."

    if password.strip() == "":
        return False, "Password khali nahi hona chahiye - kuch type karein."

    if len(password) > max_length:
        return False, f"Password bahut lamba hai (max {max_length} characters allowed)."

    if len(password) < 4:
        return False, "Password bahut chhota hai - kam se kam 4 characters likhein."

    return True, ""


# ===========================================================
#  PART 3 - Core analysis ke functions
#  (ye sab pure Python + regex + math se bane hain)
# ===========================================================

def detect_character_types(password):
    """Check karta hai password me kaun-kaun se character type hain.

    Regex ka use kiya kyunki wo pattern dhoondne me sabse easy hai.
    """
    character_types = {
        "uppercase": bool(re.search(r"[A-Z]", password)),
        "lowercase": bool(re.search(r"[a-z]", password)),
        "numbers": bool(re.search(r"[0-9]", password)),
        "special": bool(re.search(r"[^A-Za-z0-9]", password)),
    }
    return character_types


def calculate_entropy(password, character_types):
    """Password ki entropy (randomness) nikaalta hai - bits me.

    Formula: entropy = length * log2(pool_size)
    Pool size = password me use hue character types ka total count.
    Zyada entropy = hacker ke liye guess karna mushkil.
    """
    pool_size = 0
    if character_types["uppercase"]:
        pool_size += 26      # A-Z
    if character_types["lowercase"]:
        pool_size += 26      # a-z
    if character_types["numbers"]:
        pool_size += 10      # 0-9
    if character_types["special"]:
        pool_size += 33      # !@#$%^&* etc.

    # Agar koi character hi nahi hai to entropy 0 rehne dete hain (error avoid)
    if pool_size == 0 or len(password) == 0:
        return 0.0

    entropy = len(password) * math.log2(pool_size)
    return round(entropy, 2)


def is_common_password(password):
    """Password bahut famous/weak list me hai ya nahi - ye check karta hai.

    Hackers sabse pehle ye common passwords try karte hain,
    isliye inhe hum alag se mark kar rahe hain.
    """
    common_passwords = [
        "123456", "password", "12345678", "qwerty", "123456789", "12345",
        "1234", "111111", "1234567", "dragon", "123123", "baseball",
        "abc123", "football", "monkey", "letmein", "shadow", "master",
        "666666", "qwertyuiop", "123321", "654321", "superman", "1qaz2wsx",
        "7777777", "121212", "000000", "qazwsx", "123qwe", "trustno1",
        "jordan", "jennifer", "hunter", "buster", "soccer", "harley",
        "batman", "andrew", "tigger", "sunshine", "iloveyou", "charlie",
        "robert", "thomas", "hockey", "ranger", "daniel", "starwars",
        "george", "computer", "michelle", "jessica", "pepper", "1111",
        "zxcvbn", "555555", "11111111", "131313", "freedom", "777777",
        "maggie", "159753", "aaaaaa", "ginger", "princess", "joshua",
        "cheese", "amanda", "summer", "love", "ashley", "nicole", "matrix",
        "secret", "hello", "admin", "welcome", "login", "pass", "test",
        "root", "guest", "user", "p@ssw0rd", "password1", "abc12345",
    ]
    password_lower = password.lower()

    # Exact match: pura password same hai list ke kisi entry se
    if password_lower in common_passwords:
        return True

    # Substring match: password ke andar bade bade common words to nahi chhipe
    common_fragments = [
        "password", "qwerty", "iloveyou", "admin", "welcome",
        "letmein", "123456", "abc123", "football", "superman",
    ]
    for fragment in common_fragments:
        if fragment in password_lower:
            return True

    return False


def find_sequence_pattern(password):
    """1234, abcd, 9876, dcba jaisa lagatar sequence dhundhta hai.

    4 characters ka chunk lete hain aur dekhte hain ki
    values lagatar badh/ghat rahi hain ya nahi.
    """
    password_lower = password.lower()

    for index in range(len(password_lower) - 3):
        chunk = password_lower[index:index + 4]

        if chunk.isdigit():
            numbers = [int(char) for char in chunk]
            if numbers == list(range(numbers[0], numbers[0] + 4)):
                return True
            if numbers == list(range(numbers[0], numbers[0] - 4, -1)):
                return True

        if chunk.isalpha():
            letters = [ord(char) for char in chunk]
            if letters == list(range(letters[0], letters[0] + 4)):
                return True
            if letters == list(range(letters[0], letters[0] - 4, -1)):
                return True

    return False


def has_repeated_characters(password):
    """Ek hi character 3 baar ya zyada lagatar aaya hai (jaise aaa, 111)."""
    return bool(re.search(r"(.)\1{2,}", password))


def has_keyboard_pattern(password):
    """Keyboard ki lines jaise qwerty / asdfgh / zxcvbn mila ya nahi."""
    keyboard_patterns = r"(qwerty|asdfgh|zxcvbn|qazwsx|1qaz2wsx|wsxedc|ertyui|uiop)"
    return bool(re.search(keyboard_patterns, password.lower()))


def has_possible_year(password):
    """Password me birth year / saal to nahi chhupa (1950-2029)."""
    return bool(re.search(r"(19[5-9][0-9]|20[0-2][0-9])", password))


def check_weak_patterns(password):
    """Saare weak-pattern checks ko ek jagah chalata hai.

    Har issue ke saath ek penalty (nuksaan) point bhi return karta hai,
    taaki score calculation me use ho sake.
    """
    pattern_issues = []

    if is_common_password(password):
        pattern_issues.append(("Ye bahut common / guessable password hai", 50))

    if find_sequence_pattern(password):
        pattern_issues.append(("1234 / abcd jaisa sequence mila", 12))

    if has_repeated_characters(password):
        pattern_issues.append(("Ek character 3 baar repeat ho raha hai (aaa)", 10))

    if has_keyboard_pattern(password):
        pattern_issues.append(("Keyboard pattern mila (qwerty / asdfgh)", 15))

    if has_possible_year(password):
        pattern_issues.append(("Birth year / saal lagta hai use kiya", 10))

    return pattern_issues


def calculate_strength_score(length, entropy, character_types, pattern_issues):
    """Sab data se 0-100 ke beech ka final score banata hai.

    Points:
    - Length ke max 30 points
    - Har character type ke 10 points (total 40)
    - Entropy ke max 30 points
    - Weak pattern par penalty (katai)
    """
    score = 0

    # --- Length ke points (max 30) ---
    if length >= 8:
        score += 10
    if length >= 12:
        score += 10
    if length >= 16:
        score += 10

    # --- Har available character type ke 10 points (max 40) ---
    for is_present in character_types.values():
        if is_present:
            score += 10

    # --- Entropy ke points (max 30) ---
    if entropy >= 60:
        score += 30
    elif entropy >= 40:
        score += 20
    elif entropy >= 28:
        score += 10

    # --- Weak patterns ki penalty (score kabhi 0 se neeche nahi jaayega) ---
    total_penalty = sum(penalty for _message, penalty in pattern_issues)
    score -= total_penalty

    return max(0, min(100, score))


def get_strength_label(score):
    """Score ko Weak / Medium / Strong label me badalta hai."""
    if score >= 75:
        return "Strong"
    if score >= 45:
        return "Medium"
    return "Weak"


def format_time_duration(seconds):
    """Seconds ko human-friendly time me badalta hai (minutes, saal etc.)."""
    if seconds < 1:
        return "1 second se bhi kam"
    if seconds < 60:
        return f"{int(seconds)} seconds"
    if seconds < 3600:
        return f"{int(seconds // 60)} minutes"
    if seconds < 86400:
        return f"{int(seconds // 3600)} hours"
    if seconds < 31536000:
        return f"{int(seconds // 86400)} days"

    years = seconds / 31536000
    if years > 1_000_000_000:
        return "crore saal se bhi zyada (lagbhag anant)"
    if years > 1_000_000:
        return f"{years / 1_000_000:.1f} million saal"
    return f"{int(years)} saal"


def estimate_crack_time(entropy):
    """Entropy dekhkar hacker ko lagne wala approx time batata hai.

    Maan liya hacker 10^9 (1 billion) guesses per second kar sakta hai
    (modern GPU ka rough speed) - average case me aadha time lagta hai.
    """
    if entropy <= 0:
        return "turant toot jaayega"

    total_combinations = 2 ** entropy
    guesses_per_second = 1_000_000_000
    seconds_needed = total_combinations / guesses_per_second / 2

    return format_time_duration(seconds_needed)


def get_security_suggestions(length, character_types, entropy, pattern_issues):
    """User ko real-time suggestions ki list deta hai.

    Har kami (length, symbol, pattern) ke liye ek actionable tip aati hai.
    """
    suggestions = []

    if length < 12:
        suggestions.append(
            "Password ko lamba karein - kam se kam 12 characters (16+ best hai)."
        )
    if not character_types["uppercase"]:
        suggestions.append("Ek uppercase letter add karein (A-Z).")
    if not character_types["lowercase"]:
        suggestions.append("Ek lowercase letter add karein (a-z).")
    if not character_types["numbers"]:
        suggestions.append("Koi number add karein (0-9).")
    if not character_types["special"]:
        suggestions.append("Special character add karein jaise @, #, !, %, &.")

    for issue_message, _penalty in pattern_issues:
        suggestions.append(f"Ye pattern hata dein - {issue_message}")

    # Agar sab kuch theek hai phir bhi entropy kam hai to extra tip
    if entropy < 60 and not pattern_issues and length >= 12:
        suggestions.append(
            "Thoda aur random mix karein - dictionary words ke saath "
            "symbols ka combo accha rehta hai."
        )

    if not suggestions:
        suggestions.append(
            "Bahut badhiya! Password strong hai - bas kisi aur ke saath "
            "share mat karein aur har site ke liye alag rakhein."
        )

    return suggestions


def generate_security_report(
    length,
    entropy,
    character_types,
    score,
    strength_label,
    pattern_issues,
    crack_time,
):
    """Final report table banata hai (pandas DataFrame).

    Dhyan rakha ki password ki value kabhi table me nahi jaati -
    sirf analysis numbers hi hain.
    """

    def pass_fail(is_ok, ok_text="Pass", fail_text="Fail"):
        return "✅ " + ok_text if is_ok else "❌ " + fail_text

    rows = [
        {
            "Parameter": "Password Length",
            "Value": f"{length} characters",
            "Status": pass_fail(length >= 12, "12+ hai", "12 se kam hai"),
        },
        {
            "Parameter": "Estimated Entropy",
            "Value": f"{entropy} bits",
            "Status": pass_fail(entropy >= 60, "Achhi hai", "Kam hai"),
        },
        {
            "Parameter": "Uppercase Letters (A-Z)",
            "Value": "Haan" if character_types["uppercase"] else "Nahi",
            "Status": pass_fail(character_types["uppercase"], "Mil gaya", "Nahi mila"),
        },
        {
            "Parameter": "Lowercase Letters (a-z)",
            "Value": "Haan" if character_types["lowercase"] else "Nahi",
            "Status": pass_fail(character_types["lowercase"], "Mil gaya", "Nahi mila"),
        },
        {
            "Parameter": "Numbers (0-9)",
            "Value": "Haan" if character_types["numbers"] else "Nahi",
            "Status": pass_fail(character_types["numbers"], "Mil gaya", "Nahi mila"),
        },
        {
            "Parameter": "Special Characters (!@#)",
            "Value": "Haan" if character_types["special"] else "Nahi",
            "Status": pass_fail(character_types["special"], "Mil gaya", "Nahi mila"),
        },
        {
            "Parameter": "Weak / Common Patterns",
            "Value": f"{len(pattern_issues)} mile",
            "Status": pass_fail(len(pattern_issues) == 0, "Safai", "Problem mili"),
        },
        {
            "Parameter": "Estimated Crack Time",
            "Value": crack_time,
            "Status": "info",
        },
        {
            "Parameter": "Final Security Score",
            "Value": f"{score} / 100",
            "Status": strength_label,
        },
        {
            "Parameter": "Overall Result",
            "Value": strength_label,
            "Status": (
                "✅ Safe to use" if strength_label == "Strong"
                else "⚠️ Improve karein" if strength_label == "Medium"
                else "🛑 Turant badlein"
            ),
        },
    ]

    return pd.DataFrame(rows)


def analyze_password(password):
    """Poora analysis ek hi function me karke result dict deta hai.

    Ye app ka 'dil' hai - ye function sab kuch jodta hai.
    """
    character_types = detect_character_types(password)
    entropy = calculate_entropy(password, character_types)
    pattern_issues = check_weak_patterns(password)
    score = calculate_strength_score(
        len(password), entropy, character_types, pattern_issues
    )
    strength_label = get_strength_label(score)
    crack_time = estimate_crack_time(entropy)
    suggestions = get_security_suggestions(
        len(password), character_types, entropy, pattern_issues
    )
    report_table = generate_security_report(
        len(password),
        entropy,
        character_types,
        score,
        strength_label,
        pattern_issues,
        crack_time,
    )

    # Note: password khud dict me kabhi store nahi hota, sirf analysis results hain
    return {
        "length": len(password),
        "character_types": character_types,
        "entropy": entropy,
        "pattern_issues": pattern_issues,
        "score": score,
        "strength_label": strength_label,
        "crack_time": crack_time,
        "suggestions": suggestions,
        "report": report_table,
    }


# ===========================================================
#  PART 4 - Main function (page ka flow yahan set hota hai)
# ===========================================================

def main():
    """Streamlit app ka main flow - user input se report tak."""
    st.set_page_config(
        page_title="Smart Password Security Analyzer",
        page_icon="🛡️",
        layout="wide",
    )

    set_cyber_theme()
    show_sidebar()
    show_page_header()

    # Password input - type="password" hone se screen par **** dikhta hai
    password = st.text_input(
        "Apna password type karein",
        type="password",
        placeholder="jaise: MyP@ssw0rd!2026",
    )

    # Step 1: input validation
    is_valid, error_message = validate_password_input(password)
    if not is_valid:
        st.info(
            "👆 Upar wale box me password likhte hi yahan **live report** "
            "dikhne lagegi."
        )
        return

    # Step 2: analysis (basic error handling ke saath)
    try:
        result = analyze_password(password)
    except Exception:
        # Error message me password kabhi nahi dikhate (privacy rule)
        st.error("Analysis me kuch technical problem aa gayi. Dobara try karein.")
        return

    # Step 3: dashboard
    st.subheader("📊 Security Dashboard")
    show_strength_meter(result["score"], result["strength_label"])
    show_metric_row(result)
    show_character_type_cards(result["character_types"])

    # Step 4: weak pattern check
    st.subheader("⚠️ Weak Patterns & Common Password Check")
    show_pattern_issues(result["pattern_issues"])

    # Step 5: real-time suggestions
    st.subheader("💡 Real-time Security Suggestions")
    show_suggestions(result["suggestions"])

    # Step 6: final report
    st.subheader("📝 Final Security Report")
    show_final_report(result["report"])

    st.caption(
        "🔒 Reminder: Aapka password kahin store, print ya transmit nahi hua - "
        "ye analysis sirf aapke browser me chali hai."
    )


# Ye guard tab chalta hai jab directly `streamlit run app.py` se app start ho,
# test file se import karne par main() khud run nahi hota.
if __name__ == "__main__":
    main()

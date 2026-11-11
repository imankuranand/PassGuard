# ============================================================
#  Automated Test Cases - Smart Password Security Analyzer
#  -----------------------------------------------------------
#  Chalane ka tarika:  python test_analyzer.py
#  Ye file sirf functions ka logic check karti hai.
#  Koi password yahan store ya print nahi hota.
# ============================================================

from analyzer import (
    validate_password_input,
    detect_character_types,
    calculate_entropy,
    is_common_password,
    find_sequence_pattern,
    has_repeated_characters,
    check_weak_patterns,
    calculate_strength_score,
    get_strength_label,
    analyze_password,
)

# Har test ke saath counter rakhte hain
passed_tests = 0
failed_tests = 0


def run_test(test_name, actual_value, expected_value):
    """Ek test case chala kar result print karta hai."""
    global passed_tests, failed_tests

    if actual_value == expected_value:
        passed_tests += 1
        print(f"[PASS] {test_name}")
    else:
        failed_tests += 1
        print(f"[FAIL] {test_name} -> expected {expected_value}, got {actual_value}")


# ---------- 1. Input validation tests ----------
def test_input_validation():
    run_test("Khali password invalid hona chahiye",
             validate_password_input("")[0], False)
    run_test("Whitespace-only password invalid hona chahiye",
             validate_password_input("   ")[0], False)
    run_test("Normal password valid hona chahiye",
             validate_password_input("MyP@ss1")[0], True)
    run_test("Bahut lamba password (65+) invalid hona chahiye",
             validate_password_input("A1!" + "x" * 70)[0], False)
    run_test("Bahut chhota password (<4) invalid hona chahiye",
             validate_password_input("ab")[0], False)


# ---------- 2. Character detection tests ----------
def test_character_detection():
    run_test("Sabhi character types ka pata chalna chahiye",
             detect_character_types("Passw0rd!"),
             {"uppercase": True, "lowercase": True,
              "numbers": True, "special": True})

    run_test("Sirf lowercase password me sirf lowercase milna chahiye",
             detect_character_types("abcdef"),
             {"uppercase": False, "lowercase": True,
              "numbers": False, "special": False})

    run_test("Digits wale password me number milna chahiye",
             detect_character_types("123456")["numbers"], True)


# ---------- 3. Entropy tests ----------
def test_entropy():
    entropy_digits = calculate_entropy("123456", detect_character_types("123456"))
    entropy_mixed = calculate_entropy(
        "Tr0ub4dor&3", detect_character_types("Tr0ub4dor&3")
    )

    run_test("Sirf digits wale password ki entropy kam honi chahiye",
             entropy_digits < 25, True)
    run_test("Mixed password ki entropy zyada honi chahiye",
             entropy_mixed > 55, True)
    run_test("Khali string par entropy 0 aani chahiye",
             calculate_entropy("", {"uppercase": False, "lowercase": False,
                                    "numbers": False, "special": False}), 0.0)


# ---------- 4. Common password / pattern tests ----------
def test_common_patterns():
    run_test("'password' common hona chahiye", is_common_password("password"), True)
    run_test("'MyVacation2024!' common nahi hona chahiye",
             is_common_password("MyVacation2024!"), False)

    run_test("'1234' sequence hona chahiye", find_sequence_pattern("x1234x"), True)
    run_test("'abcd' sequence hona chahiye", find_sequence_pattern("zzabcdzz"), True)
    run_test("Random password me sequence nahi hona chahiye",
             find_sequence_pattern("mQ7#tR2!"), False)

    run_test("'aaa' repeated hona chahiye", has_repeated_characters("Xaaay"), True)
    run_test("Do baar repeat repeated nahi mana jaayega",
             has_repeated_characters("aab"), False)

    run_test("'password' me weak pattern milna chahiye",
             len(check_weak_patterns("password")) > 0, True)
    run_test("Strong password me koi weak pattern nahi aana chahiye",
             len(check_weak_patterns("mQ7#tR2!zP4$vL9")), 0)


# ---------- 5. Strength label tests ----------
def test_strength_labels():
    run_test("Score 90 -> Strong", get_strength_label(90), "Strong")
    run_test("Score 60 -> Medium", get_strength_label(60), "Medium")
    run_test("Score 20 -> Weak", get_strength_label(20), "Weak")
    run_test("Score 75 -> Strong (boundary)", get_strength_label(75), "Strong")
    run_test("Score 44 -> Weak (boundary)", get_strength_label(44), "Weak")


# ---------- 6. Score calculation tests ----------
def test_score_calculation():
    all_types = {"uppercase": True, "lowercase": True,
                 "numbers": True, "special": True}
    only_lower = {"uppercase": False, "lowercase": True,
                  "numbers": False, "special": False}

    strong_score = calculate_strength_score(16, 90, all_types, [])
    weak_score = calculate_strength_score(8, 30, only_lower,
                                          [("common password", 50)])

    run_test("Strong inputs par score 75+ hona chahiye", strong_score >= 75, True)
    run_test("Common password par score 45 se neeche hona chahiye",
             weak_score < 45, True)
    run_test("Score kabhi 0 se neeche nahi jaata",
             calculate_strength_score(5, 5, only_lower, [("x", 90)]) >= 0, True)
    run_test("Score kabhi 100 se upar nahi jaata",
             calculate_strength_score(64, 400, all_types, []) <= 100, True)


# ---------- 7. End-to-end (poora analyze_password) tests ----------
def test_full_analysis():
    weak_result = analyze_password("password")
    run_test("'password' Weak hona chahiye", weak_result["strength_label"], "Weak")
    run_test("'password' me common pattern milega",
             len(weak_result["pattern_issues"]) > 0, True)

    medium_result = analyze_password("Hello@123")
    run_test("'Hello@123' Medium hona chahiye",
             medium_result["strength_label"], "Medium")

    strong_result = analyze_password("mQ7#tR2!zP4$vL9")
    run_test("'mQ7#tR2!zP4$vL9' Strong hona chahiye",
             strong_result["strength_label"], "Strong")
    run_test("Strong password ki entropy 90+ honi chahiye",
             strong_result["entropy"] > 90, True)
    run_test("Length sahi calculate ho raha hai",
             strong_result["length"], 15)   # "mQ7#tR2!zP4$vL9" = 15 chars
    run_test("Report table me 10 rows honi chahiye",
             len(strong_result["report"]), 10)
    run_test("Suggestions list khali nahi honi chahiye",
             len(strong_result["suggestions"]) > 0, True)


# ---------- Sab tests chalao ----------
if __name__ == "__main__":
    print("=== Smart Password Analyzer - Test Run ===\n")

    test_input_validation()
    test_character_detection()
    test_entropy()
    test_common_patterns()
    test_strength_labels()
    test_score_calculation()
    test_full_analysis()

    print(f"\nResult: {passed_tests} passed, {failed_tests} failed")
    if failed_tests == 0:
        print("Sab tests pass ho gaye! Project chalne ke liye taiyar hai.")
    else:
        print("Kuch tests fail hue - app.py me logic check karein.")

from utils.remediation import generate_remediation

CASES = [
    ("user_fibonacci_screenshot", """// 2. Function to find the nth Fibonacci number
// Formula: F(n) = F(n-1) + F(n-2)
int fibonacci(int n) {
    // Base Case: F(0) = 0, F(1) = 1
    if (n < 1) {
        return n;
    }
    // Recursive Case: Multiple recursive calls (Tree Recursion)
    return fibonacci(n -- 1) + fibonacci(n - 2);
}"""),
    ("user_c_screenshot", "#include<stdio.h>\nint maon(){\nprintf<< \"Hi ;\nreturn 0 ;\n"),
    ("c_printf_unclosed", "#include<stdio.h>\nint main(){\nprintf(\"Hello world ;\nreturn 0;\n}"),
    ("cpp_cin_reversed", "#include<iostream>\nusing namespace std;\nint main(){\nint x;\ncin<< x;\ncout>> x;\nreturn 0;\n}"),
    ("python_missing_colon", "deff greet(name)\n    prinnt hello\n"),
    ("java_missing_semi_and_quotes", "public class Main {\n  public static void main(String[] args) {\n    Sytem.out.println(hello)\n  }\n}"),
]

for name, code in CASES:
    r = generate_remediation(code)
    print("===", name, "===")
    print("HAS_FIX:", r["has_fix"])
    print("REMAINING:", len(r["remaining_syntax_issues"]))
    print("ISSUES:", r["remaining_syntax_issues"])
    print("CHANGES:", len(r["changes"]))
    print(r["remediated"])
    print()

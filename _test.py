from utils.remediation import generate_remediation

CASES = [
    ("user1", "#include<iostream>\nusing namespace std;\nint mainnn (){\ncout<< hello;\nreturn 0;\n"),
    ("user2", "#include<iostream>\nusing namespace std;\nint main (){\ncout<<<\"hello\";\nreturn 0;\n"),
    ("python", "deff hello():\n    prinnt hello\n"),
    ("java", "public class Test {\n  public static void main(String[] args) {\n    Sytem.out.println(hello)\n  }\n"),
    ("js", "fucntion test() {\n  console.lgo(hello)\n"),
]

for name, code in CASES:
    r = generate_remediation(code)
    print("===", name, "===")
    print("HAS_FIX:", r["has_fix"])
    print("REMAINING:", len(r["remaining_syntax_issues"]))
    print("CHANGES:", len(r["changes"]))
    print(r["remediated"])
    print()

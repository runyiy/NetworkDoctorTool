from losshound.core.validation import validate_target


def test_validate_valid_ips():
    assert validate_target("8.8.8.8")
    assert validate_target("1.1.1.1")
    assert validate_target("192.168.1.1")
    assert validate_target("2001:db8::1")
    assert validate_target("[2001:db8::1]")


def test_validate_valid_hostnames():
    assert validate_target("google.com")
    assert validate_target("chatgpt.com")
    assert validate_target("my-router")
    assert validate_target("localhost")
    assert validate_target("sub.domain.co.uk")


def test_validate_invalid_empty():
    assert not validate_target("")
    assert not validate_target("   ")


def test_validate_invalid_argument_injection():
    assert not validate_target("-c")
    assert not validate_target("--help")


def test_validate_invalid_shell_injection():
    assert not validate_target("8.8.8.8 & calc.exe")
    assert not validate_target("8.8.8.8;calc")
    assert not validate_target("8.8.8.8|calc")
    assert not validate_target("`calc`")
    assert not validate_target("$(calc)")
    assert not validate_target("google.com\ncalc")
    assert not validate_target("google.com'calc")
    assert not validate_target('google.com"calc')


def test_validate_invalid_format():
    assert not validate_target(".google.com")
    assert not validate_target("google..com")
    assert not validate_target("google.com.")
    assert not validate_target("a" * 70 + ".com")  # Label too long

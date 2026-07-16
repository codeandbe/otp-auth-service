def normalize_email(email: str) -> str:
    """
    Normalize email address for consistent identity handling.

    Rules:
    1. Lowercase the entire address
    2. Strip anything after '+' in the local part (Gmail-style tag stripping)
    3. Do NOT strip dots (Gmail-specific behavior, not universal)

    Examples:
    - test+123@gmail.com -> test@gmail.com
    - test.x@gmail.com -> test.x@gmail.com (dots preserved)
    - Test@Example.COM -> test@example.com
    """
    if not email:
        return email

    email = email.lower().strip()

    if "@" not in email:
        return email

    local, domain = email.split("@", 1)

    if "+" in local:
        local = local.split("+", 1)[0]

    return f"{local}@{domain}"

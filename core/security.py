"""Local account password hashing; service methods also enforce authorization."""
from __future__ import annotations
from hashlib import pbkdf2_hmac
from hmac import compare_digest
from secrets import token_bytes
from ipaddress import ip_address

ITERATIONS = 350_000


def hash_password(password: str) -> str:
    if len(password) < 10:
        raise ValueError('Mật khẩu phải có ít nhất 10 ký tự')
    salt = token_bytes(16)
    value = pbkdf2_hmac('sha256',password.encode(),salt,ITERATIONS)
    return f'pbkdf2_sha256${ITERATIONS}${salt.hex()}${value.hex()}'


def verify_password(password: str, encoded: str) -> bool:
    try:
        alg,it,salt,digest=encoded.split('$')
        if alg!='pbkdf2_sha256':return False
        actual=pbkdf2_hmac('sha256',password.encode(),bytes.fromhex(salt),int(it))
        return compare_digest(actual,bytes.fromhex(digest))
    except (ValueError,TypeError):
        return False


def ipv4(text: str) -> str:
    addr=ip_address(text.strip())
    if addr.version!=4:raise ValueError('Chỉ hỗ trợ IPv4')
    return str(addr)


def role_check(actor, *allowed):
    if not actor or not actor['active'] or actor['system_role'] not in allowed:
        raise PermissionError('Không có quyền thực hiện thao tác này')

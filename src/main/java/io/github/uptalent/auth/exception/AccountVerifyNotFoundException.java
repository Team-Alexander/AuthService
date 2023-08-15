package io.github.uptalent.auth.exception;

public class AccountVerifyNotFoundException extends RuntimeException {
    public AccountVerifyNotFoundException() {
        super("Account not found");
    }
}

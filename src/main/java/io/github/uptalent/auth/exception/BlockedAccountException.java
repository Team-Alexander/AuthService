package io.github.uptalent.auth.exception;

public class BlockedAccountException extends RuntimeException {
    public BlockedAccountException() {
        super("Your account has been blocked. Please contact the administrator");
    }
}

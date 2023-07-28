package com.uptalent.auth.exception;

public class AccountNotFoundException extends RuntimeException{
    public  AccountNotFoundException(String message){
        super(message);
    }
}

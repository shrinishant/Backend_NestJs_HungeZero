import { Injectable } from "@nestjs/common";

@Injectable({})
export class AuthService{
    signup() {
        return "i've signed up"
    }

    signin() {
        return "i've signed in"
    }
}
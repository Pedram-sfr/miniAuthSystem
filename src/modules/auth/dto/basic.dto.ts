import { IsEmail, IsMobilePhone, IsString, Length } from "class-validator";
import { ConfirmedPassword } from "src/common/decorators/password.decorator";

export class SignupDto{
    @IsString()
    first_name: string;
    @IsString()
    last_name: string;
    @IsMobilePhone("fa-IR")
    mobile: string;
    @IsString()
    @IsEmail()
    email: string;
    @IsString()
    @Length(6,12)
    password: string;
    @IsString()
    @ConfirmedPassword("password")
    confirm_password: string;
}

export class LoginDto{
    @IsString()
    @IsEmail()
    email: string;
    @IsString()
    @Length(6,12)
    password: string;
}
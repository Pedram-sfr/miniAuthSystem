import { BadRequestException, ConflictException, Injectable, UnauthorizedException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { UserEntity } from '../user/entities/user.entity';
import { Code, Repository } from 'typeorm';
import { OTPEntity } from '../user/entities/otp.entity';
import { CheckOtpDto, SendOtpDto } from './dto/auth.dto';
import { randomInt } from 'crypto';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import { TTokenPayload } from './types/payload';
import { LoginDto, SignupDto } from './dto/basic.dto';
import { compareSync, genSaltSync, hashSync } from 'bcrypt';

@Injectable()
export class AuthService {
    constructor(
        @InjectRepository(UserEntity) private userRepository: Repository<UserEntity>,
        @InjectRepository(OTPEntity) private otpRepository: Repository<OTPEntity>,
        private jwtService: JwtService,
        private configService: ConfigService
    ) { }
    async sendOTP(otpDto: SendOtpDto) {
        const { mobile } = otpDto;
        let user = await this.userRepository.findOneBy({ mobile });
        if (!user) {
            user = this.userRepository.create({
                mobile
            })
            user = await this.userRepository.save(user)
        }
        await this.createOtpForUser(user);
        return {
            statusCode: 200,
            message: "send code!"
        }
    }

    async checkOtp(otpDto: CheckOtpDto) {
        const { code, mobile } = otpDto;
        const user = await this.userRepository.findOne({
            where: { mobile },
            relations: {
                otp: true
            }
        })
        const now = new Date();
        if (!user || !user?.otp) throw new UnauthorizedException();
        const otp = user?.otp;
        if (otp.code !== code) throw new UnauthorizedException(("OtpCode is incorect"));
        if (otp.expires_in < now) throw new UnauthorizedException("OtpCode is expired");
        if (!user.mobile_verify) {
            await this.userRepository.update({ id: user.id },
                {
                    mobile_verify: true
                }
            )
        }
        console.log(this.configService.get("Jwt.accessTokenSecret"));

        const { accessToken, refreshToken } = this.signToken({ id: user.id, mobile })
        return {
            statusCode: 200,
            data: {
                message: "Loggin OK",
                accessToken,
                refreshToken
            }
        }
    }

    async signup(signupDto: SignupDto) {
        const { first_name, last_name, email, mobile, password } = signupDto;
        await this.checkEmail(email);
        await this.checkMobile(mobile);
        let hashedPassword = this.hashedPassword(password);
        const user = this.userRepository.create({
            first_name, last_name, email, mobile, password: hashedPassword
        });
        await this.userRepository.save(user);
        return {
            message: "user signup!"
        }
    }

    async login(loginDto: LoginDto) {
        const { email, password } = loginDto
        const user = await this.userRepository.findOneBy({ email })
        if (!user)
            throw new UnauthorizedException("Email Or Passwor is Incorect")
        if (!compareSync(password, user.password))
            throw new UnauthorizedException("Email Or Passwor is Incorect")
        const {accessToken, refreshToken} = this.signToken({mobile: user.mobile, id: user.id});
        return {
            message: "Loging :)",
            data:{
                accessToken,
                refreshToken
            }
        }
    }

    async checkEmail(email: string) {
        const user = await this.userRepository.findOneBy({ email });
        if (user) throw new ConflictException("email already exist!")
    }
    async checkMobile(mobile: string) {
        const user = await this.userRepository.findOneBy({ mobile });
        if (user) throw new ConflictException("mobile already exist!")
    }

    async createOtpForUser(user: UserEntity) {
        const code = randomInt(10000, 99999).toString();
        const expiresIn = new Date(new Date().getTime() + 1000 * 60 * 2)
        let otp = await this.otpRepository.findOneBy({ userId: user.id })
        if (otp) {
            if (otp.expires_in > new Date()) throw new BadRequestException("OtpCode not Expired!")
            otp.code = code;
            otp.expires_in = expiresIn;
        } else {
            otp = this.otpRepository.create({
                code,
                expires_in: expiresIn,
                userId: user.id
            })
        }
        otp = await this.otpRepository.save(otp);
        user.otpId = otp.id;
        await this.userRepository.save(user);
    }

    signToken(payload: TTokenPayload) {
        const accessToken = this.jwtService.sign(
            payload,
            {
                secret: this.configService.get("Jwt.accessTokenSecret"),
                expiresIn: "30d"
            })
        const refreshToken = this.jwtService.sign(
            payload, {
            secret: this.configService.get("Jwt.refreshTokenSecret"),
            expiresIn: "1y"
        })

        return {
            accessToken,
            refreshToken
        }
    }

    async validateAccessToken(token: string) {
        try {
            const payload = this.jwtService.verify<TTokenPayload>(token, {
                secret: this.configService.get("Jwt.accessTokenSecret")
            })
            if (typeof payload === "object" && payload?.id) {
                const user = this.userRepository.findOneBy({ id: payload.id })
                if (!user)
                    throw new UnauthorizedException("invalid Token!")
                return user
            }
            throw new UnauthorizedException("invalid Token!")
        } catch (error) {
            throw new UnauthorizedException("invalid Token!")
        }
    }

    hashedPassword(password: string) {
        const salt = genSaltSync(10)
        return hashSync(password, salt);
    }
}

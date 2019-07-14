import { Repository, EntityRepository } from 'typeorm';
import { User } from './user.entity';
import { AuthCredentialDto } from './dto/auth-credential.dto';
import {
  ConflictException,
  InternalServerErrorException,
} from '@nestjs/common';
import * as bcrypt from 'bcrypt';

@EntityRepository(User)
export class UserRepository extends Repository<User> {
  async signUp(authCredentialDto: AuthCredentialDto) {
    const { username, password } = authCredentialDto;
    // const salt = await bcrypt.genSalt();

    const user = new User();
    user.username = username;
    user.salt = await bcrypt.genSalt();
    // console.log(user.salt);
    user.password = await this.hashPassword(password, user.salt);

    // console.log(user.password);
    try {
      await user.save();
    } catch (error) {
      // console.log(error.code);
      if (error.code === '23505') {
        // duplicate username
        throw new ConflictException('Username already exist');
      } else {
        throw new InternalServerErrorException();
      }
    }
  }

  async validateUserPassword(
    authCredentialDto: AuthCredentialDto,
  ): Promise<string> {
    const { username, password } = authCredentialDto;
    const user = await this.findOne({ username });

    if (user && (await user.validatePassword(password))) {
      return user.username;
    } else {
      return null;
    }
  }

  private async hashPassword(password: string, salt: string): Promise<string> {
    return await bcrypt.hash(password, salt);
  }
}

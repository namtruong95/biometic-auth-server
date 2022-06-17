import fs from 'fs';
import util from 'util';
const readFile = util.promisify(fs.readFile);
import { UserDto } from '../types/user';

const usersFilePath = __dirname + '/../../data/users.json';

export const getUserByEmail = (email: string) => {
  return readFile(usersFilePath, 'utf8').then((res) => {
    const users = JSON.parse(res) as UserDto[];

    const user = users.find((u) => u.email === email);
    return user;
  });
};

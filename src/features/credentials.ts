import { StoredCredential } from '../types/credential';
import fs from 'fs';
import util from 'util';
const readFile = util.promisify(fs.readFile);

const credentialsFilePath = __dirname + '/../../data/credentials.json';

export const readCredentials = (): Promise<StoredCredential[]> => {
  return readFile(credentialsFilePath, 'utf8').then((res) => JSON.parse(res));
};

export const getCredentialById = (
  credentialID: string
): Promise<StoredCredential | undefined> => {
  return readFile(credentialsFilePath, 'utf8').then((res) => {
    const credentials = JSON.parse(res) as StoredCredential[];

    return credentials.find((c) => c.credentialID === credentialID);
  });
};

export const writeCredential = (credential: StoredCredential) => {
  fs.readFile(credentialsFilePath, 'utf8', (err, data) => {
    if (err) {
      console.log(err);
      return;
    }

    const oldCredentials = JSON.parse(data) as Array<StoredCredential>;
    oldCredentials.push(credential);

    fs.writeFile(
      credentialsFilePath,
      JSON.stringify(oldCredentials),
      'utf8',
      () => {}
    );
  });
};

export const updateUserCredential = (credential: StoredCredential) => {
  fs.readFile(credentialsFilePath, 'utf8', (err, data) => {
    if (err) {
      console.log(err);
      return;
    }

    const oldCredentials = JSON.parse(data) as Array<StoredCredential>;
    const existCredentialIndex = oldCredentials.findIndex(
      (c) => c.user_id === credential.user_id
    );

    if (existCredentialIndex >= 0) {
      oldCredentials[existCredentialIndex] = credential;
    } else {
      oldCredentials.push(credential);
    }

    fs.writeFile(
      credentialsFilePath,
      JSON.stringify(oldCredentials),
      'utf8',
      () => {}
    );
  });
};

export const updateCredential = (credential: StoredCredential) => {
  fs.readFile(credentialsFilePath, 'utf8', (err, data) => {
    if (err) {
      console.log(err);
      return;
    }

    const oldCredentials = JSON.parse(data) as Array<StoredCredential>;
    const index = oldCredentials.findIndex(
      (item) => item.credentialID === credential.credentialID
    );

    if (index >= 0) {
      oldCredentials[index] = credential;
      fs.writeFile(
        credentialsFilePath,
        JSON.stringify(oldCredentials),
        'utf8',
        () => {}
      );
    }
  });
};

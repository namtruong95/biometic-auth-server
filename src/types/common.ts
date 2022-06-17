import {
  PublicKeyCredentialCreationOptionsJSON,
  PublicKeyCredentialRequestOptionsJSON,
} from '@simplewebauthn/typescript-types';

export interface UserInfo {
  user_id: string;
  name: string;
  displayName: string;
  picture: string;
}

export interface WebAuthnRegistrationObject
  extends Omit<
    PublicKeyCredentialCreationOptionsJSON,
    'rp' | 'pubKeyCredParams'
  > {
  credentialsToExclude?: string[];
  customTimeout?: number;
  abortTimeout?: number;
}

export interface WebAuthnAuthenticationObject
  extends PublicKeyCredentialRequestOptionsJSON {
  customTimeout?: number;
  abortTimeout?: number;
}

export interface CustomHeadersDto {
  'X-User-Email': string;
  'X-Challenge'?: string;
}

export enum CustomHeadersEnum {
  userEmail = 'X-User-Email',
  challenge = 'X-Challenge',
}

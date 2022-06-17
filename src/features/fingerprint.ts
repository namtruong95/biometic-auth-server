import { getUserByEmail } from './user';
import express, { Request, Response, Router } from 'express';
import {
  WebAuthnAuthenticationObject,
  WebAuthnRegistrationObject,
} from '../types/common';
import { createHash } from 'crypto';
import base64url from 'base64url';
import {
  AuthenticationCredentialJSON,
  AuthenticatorDevice,
  PublicKeyCredentialUserEntityJSON,
  RegistrationCredentialJSON,
} from '@simplewebauthn/typescript-types';
import {
  generateAuthenticationOptions,
  generateRegistrationOptions,
  verifyAuthenticationResponse,
  verifyRegistrationResponse,
} from '@simplewebauthn/server';
import { StoredCredential } from '../types/credential';
import {
  getCredentialById,
  updateCredential,
  updateUserCredential,
} from './credentials';

const DEFAULT_TIMEOUT = 1000 * 60 * 5; // 5 minutes
const RP_NAME = process.env.PROJECT_NAME || 'Demo Auth';
const DEFAULT_ORIGIN = ['http://localhost:4202'];

const router: Router = express.Router();

router.post('/registerRequest', async (req: Request, res: Response) => {
  if (!res.locals.hostname) {
    res.status(400).json({ error: 'Hostname not configured.' });
    return;
  }
  const userEmail = res.locals.userEmail;

  const userDB = await getUserByEmail(userEmail);

  if (!userDB) {
    res.status(400).json({ error: 'user not found.' });
    return;
  }

  try {
    const creationOptions = <WebAuthnRegistrationObject>req.body || {};

    const pubKeyCredParams: PublicKeyCredentialParameters[] = [];

    const params = [-7, -257];
    for (let param of params) {
      pubKeyCredParams.push({ type: 'public-key', alg: param });
    }
    const authenticatorSelection: AuthenticatorSelectionCriteria = {};
    const aa = creationOptions.authenticatorSelection?.authenticatorAttachment;
    const rk = creationOptions.authenticatorSelection?.residentKey;
    const uv = creationOptions.authenticatorSelection?.userVerification;
    const cp = creationOptions.attestation; // attestationConveyancePreference
    let attestation: AttestationConveyancePreference = 'none';

    if (aa === 'platform' || aa === 'cross-platform') {
      authenticatorSelection.authenticatorAttachment = aa;
    }

    if (rk === 'required' || rk === 'preferred' || rk === 'discouraged') {
      authenticatorSelection.residentKey = rk;
    }
    if (uv === 'required' || uv === 'preferred' || uv === 'discouraged') {
      authenticatorSelection.userVerification = uv;
    }
    if (
      cp === 'none' ||
      cp === 'indirect' ||
      cp === 'direct' ||
      cp === 'enterprise'
    ) {
      attestation = cp as AttestationConveyancePreference;
    }

    const encoder = new TextEncoder();

    const name = userDB.name || creationOptions.user?.name || 'Unnamed User';
    const displayName =
      userDB.name || creationOptions.user?.displayName || 'Unnamed User';
    const data = encoder.encode(userEmail);
    const userId = createHash('sha256').update(data).digest();

    const user = {
      id: base64url.encode(Buffer.from(userId)),
      name,
      displayName,
    } as PublicKeyCredentialUserEntityJSON;

    const extensions = creationOptions.extensions;
    const timeout = creationOptions.customTimeout || DEFAULT_TIMEOUT;

    const options = generateRegistrationOptions({
      rpName: RP_NAME,
      rpID: res.locals.hostname,
      userID: user.id,
      userName: user.name,
      userDisplayName: user.displayName,
      timeout,
      // Prompt users for additional information about the authenticator.
      attestationType: attestation,
      // Prevent users from re-registering existing authenticators
      authenticatorSelection,
      extensions,
    });

    res.json(options);
  } catch (error) {
    console.error(error);
    res.status(400).send({ status: false, error: error });
  }
});

router.post('/registerResponse', async (req: Request, res: Response) => {
  const challenge = res.locals.challenge;
  if (!challenge) {
    res.status(400).json({ error: 'No challenge found.' });
    return;
  }

  const userEmail = res.locals.userEmail;
  const userDB = await getUserByEmail(userEmail);
  if (!userDB) {
    res.status(400).json({ error: 'user not found.' });
    return;
  }

  if (!res.locals.hostname) {
    res.status(400).json({ error: 'Hostname not configured.' });
  }

  if (!res.locals.origin) {
    res.status(400).json({ error: 'Origin not configured.' });
    return;
  }

  try {
    const credential = <RegistrationCredentialJSON>req.body;

    const expectedRPID = res.locals.hostname;

    let expectedOrigin = DEFAULT_ORIGIN;

    const verification = await verifyRegistrationResponse({
      credential,
      expectedChallenge: challenge,
      expectedOrigin,
      expectedRPID,
    });

    const { verified, registrationInfo } = verification;

    if (!verified || !registrationInfo) {
      throw 'User verification failed.';
    }

    const { credentialPublicKey, credentialID, counter } = registrationInfo;
    const base64PublicKey = base64url.encode(credentialPublicKey);
    const base64CredentialID = base64url.encode(credentialID);
    const { transports, clientExtensionResults } = credential;

    const result = {
      user_id: userEmail,
      credentialID: base64CredentialID,
      credentialPublicKey: base64PublicKey,
      counter,
      registered: new Date().getTime(),
      user_verifying: registrationInfo.userVerified,
      authenticatorAttachment: 'platform',
      browser: req.useragent?.browser,
      os: req.useragent?.os,
      platform: req.useragent?.platform,
      transports,
      clientExtensionResults,
    } as StoredCredential;

    updateUserCredential(result);

    res.json(result);
  } catch (error: any) {
    console.error(error);
    res.status(400).send({ status: false, error: error.message });
  }
});

router.post('/authRequest', async (req: Request, res: Response) => {
  if (!res.locals.hostname) {
    res.status(400).json({ error: 'Hostname not configured.' });
    return;
  }

  const userEmail = res.locals.userEmail;
  const userDB = await getUserByEmail(userEmail);
  if (!userDB) {
    res.status(400).json({ error: 'user not found.' });
    return;
  }

  try {
    const requestOptions = <WebAuthnAuthenticationObject>req.body;

    const userVerification = requestOptions.userVerification || 'preferred';
    const timeout = requestOptions.customTimeout || DEFAULT_TIMEOUT;
    const rpID = res.locals.hostname;

    const options = generateAuthenticationOptions({
      timeout,
      userVerification,
      rpID,
    });

    res.json(options);
  } catch (error) {
    console.error(error);

    res.status(400).json({ status: false, error });
  }
});

router.post('/authResponse', async (req: Request, res: Response) => {
  const challenge = res.locals.challenge;
  if (!challenge) {
    res.status(400).json({ error: 'No challenge found.' });
    return;
  }

  if (!res.locals.hostname) {
    res.status(400).json({ error: 'Hostname not configured.' });
    return;
  }

  if (!res.locals.origin) {
    res.status(400).json({ error: 'Origin not configured.' });
    return;
  }

  const userEmail = res.locals.userEmail;
  const userDB = await getUserByEmail(userEmail);
  if (!userDB) {
    res.status(400).json({ error: 'user not found.' });
    return;
  }

  // const user = res.locals.user;
  const expectedChallenge = res.locals.challenge;
  const expectedRPID = res.locals.hostname;
  const expectedOrigin = DEFAULT_ORIGIN;

  try {
    const claimedCred = <AuthenticationCredentialJSON>req.body;

    // call API get credential from DB
    const storedCred: StoredCredential | undefined = await getCredentialById(
      claimedCred.id
    );

    if (!storedCred) {
      res.status(400).json({ error: 'Authenticating credential not found.' });
      return;
    }

    const base64PublicKey = base64url.toBuffer(storedCred.credentialPublicKey);
    const base64CredentialID = base64url.toBuffer(storedCred.credentialID);
    const { counter, transports } = storedCred;

    const authenticator: AuthenticatorDevice = {
      credentialPublicKey: base64PublicKey,
      credentialID: base64CredentialID,
      counter,
      transports,
    };

    const verification = verifyAuthenticationResponse({
      credential: claimedCred,
      expectedChallenge,
      expectedOrigin,
      expectedRPID,
      authenticator,
    });

    const { verified, authenticationInfo } = verification;

    if (!verified) {
      res.status(400).json({ error: 'User verification failed.' });
      return;
    }

    storedCred.counter = authenticationInfo.newCounter || storedCred.counter++;
    storedCred.last_used = new Date().getTime();

    updateCredential(storedCred);

    res.json({
      token: new Date().getTime().toString(),
      credential: storedCred,
    });
  } catch (error) {
    console.error(error);

    res.status(400).json({ status: false, error });
  }
});

export { router as fingerprint };

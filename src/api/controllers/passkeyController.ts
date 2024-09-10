import {
  generateAuthenticationOptions,
  GenerateAuthenticationOptionsOpts,
  generateRegistrationOptions,
  verifyAuthenticationResponse,
  VerifyAuthenticationResponseOpts,
  verifyRegistrationResponse,
  VerifyRegistrationResponseOpts,
} from '@simplewebauthn/server';
import CustomError from '../../classes/CustomError';
import {Challenge, PasskeyUserGet} from '../../types/PasskeyTypes';
import challengeModel from '../models/challengeModel';
import passkeyUserModel from '../models/passkeyUserModel';
import fetchData from '../../utils/fetchData';
import {NextFunction, Request, Response} from 'express';
import {
  AuthenticationResponseJSON,
  PublicKeyCredentialCreationOptionsJSON,
  PublicKeyCredentialRequestOptionsJSON,
  RegistrationResponseJSON,
} from '@simplewebauthn/server/script/deps';
import {User} from '@sharedTypes/DBTypes';
import {LoginResponse, UserResponse} from '@sharedTypes/MessageTypes';
import authenticatorDeviceModel from '../models/authenticatorDeviceModel';
import jwt from 'jsonwebtoken';

// check environment variables
if (
  !process.env.NODE_ENV ||
  !process.env.RP_ID ||
  !process.env.AUTH_URL ||
  !process.env.JWT_SECRET ||
  !process.env.RP_NAME
) {
  throw new Error('Environment variables not set');
}

const {NODE_ENV, RP_ID, AUTH_URL, JWT_SECRET, RP_NAME} = process.env;

// Registration handler
const setupPasskey = async (
  req: Request<{}, {}, User>,
  res: Response<{
    email: string;
    options: PublicKeyCredentialCreationOptionsJSON;
  }>,
  next: NextFunction,
) => {
  try {
    // Register user with AUTH API
    const options: RequestInit = {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(req.body),
    };
    const userResponse = await fetchData<UserResponse>(
      process.env.AUTH_URL + '/api/v1/users',
      options,
    );

    if (!userResponse) return next(new CustomError('User not created', 400));

    const regOptions = await generateRegistrationOptions({
      rpName: RP_NAME,
      rpID: RP_ID,
      userName: userResponse.user.username,
      attestationType: 'none',
      timeout: 60000,
      authenticatorSelection: {
        residentKey: 'discouraged',
        userVerification: 'preferred',
      },
      supportedAlgorithmIDs: [-7, -257],
    });

    const challenge: Challenge = {
      email: userResponse.user.email,
      challenge: regOptions.challenge,
    };

    await new challengeModel(challenge).save();

    await new passkeyUserModel({
      email: userResponse.user.email,
      userId: userResponse.user.user_id,
      devices: [],
    }).save();

    res.json({
      email: userResponse.user.email,
      options: regOptions,
    });
  } catch (error) {
    next(new CustomError((error as Error).message, 500));
  }
};

// Registration verification handler
const verifyPasskey = async (
  req: Request<
    {},
    {},
    {email: string; registrationOptions: RegistrationResponseJSON}
  >,
  res: Response<UserResponse>,
  next: NextFunction,
) => {
  try {
    const expectedChallenge = await challengeModel.findOne({
      email: req.body.email,
    });
    if (!expectedChallenge)
      return next(new CustomError('Challenge not found', 404));

    const opts: VerifyRegistrationResponseOpts = {
      response: req.body.registrationOptions,
      expectedChallenge: expectedChallenge.challenge,
      expectedOrigin:
        NODE_ENV === 'development'
          ? `http://${RP_ID}:5173`
          : `https://${RP_ID}`,
      expectedRPID: RP_ID,
    };

    const verification = await verifyRegistrationResponse(opts);
    const {verified, registrationInfo} = verification;
    if (!verified || !registrationInfo)
      return next(new CustomError('Verification failed', 403));

    const {credentialPublicKey, credentialID, counter} = registrationInfo;
    const existingDevice = await authenticatorDeviceModel.findOne({
      credentialID,
    });
    if (existingDevice)
      return next(new CustomError('Device already registered', 400));

    const newDevice = await new authenticatorDeviceModel({
      email: req.body.email,
      credentialID,
      credentialPublicKey: Buffer.from(credentialPublicKey),
      counter,
      transports: req.body.registrationOptions.response.transports,
    }).save();

    const user = await passkeyUserModel.findOne({
      email: req.body.email,
    });
    if (!user) return next(new CustomError('User not found', 404));
    user.devices.push(newDevice._id);
    await user.save();

    await challengeModel.findOneAndDelete({email: req.body.email});

    const response = await fetchData<UserResponse>(
      AUTH_URL + '/api/v1/users/' + user.userId,
    );
    res.json(response);
  } catch (error) {
    next(new CustomError((error as Error).message, 500));
  }
};

// Generate authentication options handler
const authenticationOptions = async (
  req: Request<{}, {}, {email: string}>,
  res: Response<PublicKeyCredentialRequestOptionsJSON>,
  next: NextFunction,
) => {
  try {
    const user = (await passkeyUserModel
      .findOne({email: req.body.email})
      .populate('devices')) as unknown as PasskeyUserGet;
    if (!user) return next(new CustomError('User not found', 404));

    const opts: GenerateAuthenticationOptionsOpts = {
      timeout: 60000,
      allowCredentials: user.devices.map((device) => ({
        id: device.credentialID,
        type: 'public-key',
        transports: device.transports,
      })),
      userVerification: 'preferred',
      rpID: RP_ID,
    };
    const authOptions = await generateAuthenticationOptions(opts);

    await new challengeModel({
      email: req.body.email,
      challenge: authOptions.challenge,
    }).save();

    res.send(authOptions);
  } catch (error) {
    next(new CustomError((error as Error).message, 500));
  }
};

// Authentication verification and login handler
const verifyAuthentication = async (
  req: Request<
    {},
    {},
    {email: string; authResponse: AuthenticationResponseJSON}
  >,
  res: Response<LoginResponse>,
  next: NextFunction,
) => {
  try {
    const {email, authResponse} = req.body;

    const expectedChallenge = await challengeModel.findOne({
      email,
    });
    if (!expectedChallenge)
      return next(new CustomError('Challenge not found', 404));

    const user = (await passkeyUserModel
      .findOne({email})
      .populate('devices')) as unknown as PasskeyUserGet;
    if (!user) return next(new CustomError('User not found', 404));

    const opts: VerifyAuthenticationResponseOpts = {
      response: authResponse,
      expectedChallenge: expectedChallenge.challenge,
      expectedOrigin:
        NODE_ENV === 'development'
          ? `http://${RP_ID}:5173`
          : `https://${RP_ID}`,
      expectedRPID: RP_ID,
      authenticator: {
        credentialID: user.devices[0].credentialID,
        credentialPublicKey: Buffer.from(user.devices[0].credentialPublicKey),
        counter: user.devices[0].counter,
      },
    };

    const verification = await verifyAuthenticationResponse(opts);
    const {verified, authenticationInfo} = verification;
    if (!verified)
      await authenticatorDeviceModel.findOneAndUpdate(user.devices[0]._id, {
        counter: authenticationInfo.newCounter,
      });

    await challengeModel.findOneAndDelete({email: email});

    const userResponse = await fetchData<UserResponse>(
      AUTH_URL + '/api/v1/users/' + user.userId,
    );
    const token = jwt.sign(
      {
        user_id: userResponse.user.user_id,
        level_name: userResponse.user.level_name,
      },
      JWT_SECRET,
      {
        expiresIn: '24h',
      },
    );

    res.json({
      message: 'Login successful',
      token,
      user: userResponse.user,
    });
  } catch (error) {
    next(new CustomError((error as Error).message, 500));
  }
};

export {
  setupPasskey,
  verifyPasskey,
  authenticationOptions,
  verifyAuthentication,
};

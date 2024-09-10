import type {Base64URLString, AuthenticatorDevice} from '@simplewebauthn/types';
import { Types} from 'mongoose';

// when inserting to a collection
type PasskeyUserPost = {
  userId: number;
  email: string;
  devices: Types.ObjectId[];
};

// when fetching from a collection
type PasskeyUserGet = {
  userId: number;
  email: string;
  devices: AuthDevice[];
};

type AuthDevice = AuthenticatorDevice & {
  _id: Types.ObjectId;
  email: string;
};

type Challenge = {
  challenge: Base64URLString;
  email: string;
};

export {AuthDevice, PasskeyUserPost, PasskeyUserGet, Challenge};

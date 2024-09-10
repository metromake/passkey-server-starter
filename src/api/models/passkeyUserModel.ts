import {model, Schema} from 'mongoose';
import {PasskeyUserPost} from '../../types/PasskeyTypes';

const PasskeyUserSchema = new Schema<PasskeyUserPost>({
  userId: {
    type: Number,
    required: true,
    unique: true,
  },
  email: {
    type: String,
    required: true,
    unique: true,
  },
  devices: [
    {
      type: [Schema.Types.ObjectId],
      required: true,
      ref: 'AuthenticatorDevice',
    },
  ],
});

export default model<PasskeyUserPost>('PasskeyUser', PasskeyUserSchema);

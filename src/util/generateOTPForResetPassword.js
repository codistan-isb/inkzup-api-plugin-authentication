export default async function generateOTPForResetPassword() {
  // Generate a random 6-digit number
  const otp = Math.floor(1000 + Math.random() * 9000);

  // Set expiration time to 5 minutes from now
  const expirationTime = Date.now() + 15 * 60 * 1000; // in milliseconds
  console.log("OTP: ", otp);
  console.log("Expiration Time: ", expirationTime);
  return { otp, expirationTime };
}

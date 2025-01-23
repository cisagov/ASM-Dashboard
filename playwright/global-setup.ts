import { chromium, FullConfig} from '@playwright/test';
import * as OTPAuth from 'otpauth';
import * as dotenv from 'dotenv';

dotenv.config();

const authFile = './storageState.json';

let totp = new OTPAuth.TOTP({
  issuer: process.env.PW_XFD_2FA_ISSUER,
  label: 'Crossfeed',
  algorithm: 'SHA1',
  digits: 6,
  period: 30,
  secret: process.env.PW_XFD_2FA_SECRET
});

async function globalSetup(config: FullConfig) {

  const browser = await chromium.launch();
  const page = await browser.newPage();

  //Log in with credentials.
  await page.goto(String(process.env.PW_XFD_URL));
  await page.getByTestId('button').click();
  await page
    .getByLabel('Username (Email)')
    .fill(String(process.env.PW_XFD_USERNAME));
  await page.getByRole('button', { name: 'Next' }).click();
  await page
    .getByLabel('Email address')
    .fill(String(process.env.PW_XFD_USERNAME));
  await page
    .getByLabel('Password', { exact: true })
    .fill(String(process.env.PW_XFD_PASSWORD));
  await page.getByRole('button', { name: 'Sign in' }).click();
  await page.getByLabel('One-time code').fill(totp.generate());
  await page.getByRole('button', { name: 'Submit' }).click();
  //Wait for storageState to write to json file for other tests to use.
  await page.waitForTimeout(7000);
  await page.context().storageState({ path: authFile });
  await page.close();
}

export default globalSetup;

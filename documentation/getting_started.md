# Getting Started

Updated the 26th of October 2024.

Download the Talao or Altme wallet from the Apple store or Google Play Store.

* Talao

  * [Google store](https://play.google.com/store/apps/details?id=co.talao.wallet&hl=fr)
  * [Apple store](https://apps.apple.com/fr/app/talao-wallet/id1582183266?platform=iphone)
* Altme

  * [Google store](https://play.google.com/store/apps/details?id=co.altme.alt.me.altme&hl=en-US&pli=1)
  * [Apple store](https://apps.apple.com/fr/app/altme-wallet/id1633216869)

If it is the first install open the app, clic on create a wallet, setup the PIN code or Biometric, read and agree the Terms and Conditions, clic on Start. Wallet will display the main screen "My wallet".

## Initial setup

Like any other smartphone app, user must initialize their wallet first. 2 options are proposed:

* Restore a wallet : users have previously saved their private keys through a passphrase in this app or in another wallet. they can recover their private keys.
* Create a wallet: for new users.

They will be then asked to choose their mean of authentication as a PIN code, a biometric or both to get a more secure 2 factors authentication. If a PIN code is chosen, confirmation will be requested.

Nota Bene:

* in case of 3 wrong PIN codes, the wallet will delete the wallet data stored in the smartphone and will restart from scratch. In that situation all data and keys could be lost if user did not backup before,
* the restore wallet option allow users to recover the private keys of their identity (DID), the verifiable credentials data and eventually the private keys of their crypto accounts (Altme wallet).

In case of Altme wallet a specific step will be proposed to backup the new passphrase. If the wallet is used to manage crypto assets, it is highly recommended to keep a copy of this passphrase.

## Get a proof of email

To get a proof of an email address clic [here](https://issuer.talao.co/emailpass?draft=11&format=ldp_vc) and:

1. follow the process, enter your email, enter the secret code received by email,
2. if you use your desktop scan the QR code if use your smartphone clic on the logo of the wallet installed (Altme or Talao),
3. allow access to domain talao.io,
4. select the credential you consent to receive,
5. clic on MY WALLET in the bottom bar to see the credential in the wallet.

You have now your first verifiable credential, if you clic on the green card "Proof of email" you will see your email which is the data of the credential. This credential has been issued by Talao. It has been signed after verifying the value of the secret code entered. It is a proof of the ownership of an email address as a verifiable credential.

## Get a proof of age (over 18) with an instant picture

Let's get a proof of age estimated with an instant picture analyzed by an Articifial Intelligence engine:

1. open the wallet app,
2. from main screen clic on DISCOVER in the bottom bar,
3. clic on Proof of over 18, clic on GET THIS CARD,
4. clic on Quick photo of you (1 min)
5. follow the process,
6. clic on MY WALLET in the bottom bar

## Get an Digital ID card with your passport or ID card

To get a Digital ID clic [here](https://talao.co/id360/oidc4vc?format=ldp_vc&draft=11&type=verifiableid) and:

1. process carefully the video recognition and document authentication steps,
2. open the wallet app,
3. if you use your desktop scan the QR code if use your smartphone clic on the logo of the wallet installed (Altme or Talao),
4. allow access to domain talao.io,
5. select the credential you consent to receive,
6. clic on MY WALLET in the bottom bar to see the credential in the wallet.

You have now a proof of age. The age verification has been provided by our partner [Yoti](https://www.yoti.com/business/age-verification/) thanks to an AI engine. This credential has been issued by Talao. It is a proof of age as a verifiable credential.

## Present a proof age

Let's now present this proof of age to the age verification tool setup by our partner [Werify](https://werify.eu/):

1. Clic [here]([https://staging.werify.eu/#/werify_point_kiosk/attempt+ideology+glamorous+varsity+spelling](https://staging.werify.eu/#/werify_point_kiosk/attempt+ideology+glamorous+varsity+spelling)) to go to the verifier website,
2. scan the QR code with the wallet scanner.

You have used your age credential to prove your age. This tools is a verifier managed by Werify.

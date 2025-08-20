# Wallet configuration

Updated the 14th of October 2024.

After defining a configuration in the web application it is possible to configure the wallet by scanning a QR code with the app camera.

## Examples of configurations with QR code

You can use these QR codes when the wallet app **is already installed** on your smartphone.

[**Simple Wallet**](https://wallet-provider.talao.co/configuration/webpage?login=guest@SimpleWallet&password=guest&wallet-provider=https://wallet-provider.talao.co) demonstrates how one can simplify the interface, change titles, colors and logos. Open the Talao or Altme wallet app and scan the QR code of the link. Reset the wallet if needed as only one configuration is allowed.

[**EUDI wallet**](https://wallet-provider.talao.co/configuration/webpage?login=guest@EUDI&password=guest&wallet-provider=https://wallet-provider.talao.co) is the configuration to integrate the wallet in an ARF ecosystem.Open the Talao or Altme wallet app and scan the QR code of the link. Reset the wallet if needed as only one configuration is allowed.

## Examples of installation links

You can use these links when the wallet app **is not installed** on your smartphone.

If users click on these links inside the smartphone (in an email, SMS, or in the browser), the link will redirect users to the Apple or Google stores and then the wallet will download the configuration automatically.

Simple Wallet link: `https://app.talao.co/install?password=guest&login=guest@SimpleWallet&wallet-provider=https://wallet-provider.talao.co`

EUDI wallet link: `https://app.talao.co/install?password=guest&login=guest@EUDI&wallet-provider=https://wallet-provider.talao.co`

Copy the link. The link must be used with the smartphone inside an email, an SMS or on the smartphone browser. To test the link with your own smartphone, remove the wallet app from your smartphone.

For iphone users, you need to remove the wallet cache first as the removal of the app is not enough. The way to do it is :

- open the Talao or Altme wallet,
- enter 3 wrong PINs,
- delete the account,
- remove the app.

## Update the configuration

If you update the configuration on the Wallet Provider Backend, users must download the new configuration to their wallet instance to take advantage of the new features. To do that they can clic on the "Update your wallet config now" option in the settings menu.

You can send a notification to alert all users through the notification services offered by the Wallet Provider Backend.





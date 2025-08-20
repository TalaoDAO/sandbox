# Issuer Marketplace

Updated the 14th of October 2024.

The issuer marketplace makes it possible to provide a link to a verifiable credentials issuer in the wallet. The Wallet Provider Backend allows in particular to add one of Talao's issuers to the wallet configuration, but it also allows to add a link to an external issuer made by a third party. For an issuer to be added, it simply needs to be accessible in the smartphone's browser and implement the OIDC4VCI protocol used by the wallet.

The possibility of making available the links to the most important issuers in the wallet itself brings great comfort of use and also helps to avoid identity fraud at the issuer.

Issuer links are displayed in the wallet DISCOVER screen as a "card".

## Add a Talao issuer

Talao has developed several issuers that are immediately available. They are compatible with almost all verifiable credential offerings. In particular:

* an issuer of email account proof. It is available for the VC formats ldp_vc, jwt_vc_json and sd-jwt vc. The user is redirected to a web site that requests him to enter his email. He then receives a code by email that he must enter to validate the verification, This issuer is available in the Talao and Altme wallet available from the stores. Thanks to the issuer marketplace you can add it to your configuration,
* an issuer of phone number proof. It is available for the VC formats ldp_vc, jwt_vc_json and sd-jwt vc. The user is redirected to a web site that requests him to enter his phone number. He then receives a code by SMS that he must enter to validate the verification, This issuer is available in the Talao and Altme wallet available from the stores. Thanks to the issuer marketplace you can add it to your configuration,
* an issuer of proof of age for over 13 yo, over 15 yo, over 18 yo, over 21 yo, over 50 yo and over 65 yo. This issuer is available with 2 different processes:
  * with a photo analyzed by an Artificial Intelligence. The proof of age is done in less than a minute using the phone's camera. The processing is provided by our partner [YOTI](https://www.yoti.com/business/age-verification/). This issuer is only available for VC formats of the ldp_vc type.
  * with an identity document verification. The processing is done by our partner [Docaposte](https://www.docaposte.com/) and uses the [ID360 platform](https://www.docaposte.com/solutions/id360). This issuer supports all verifiable credentials formats: ldp_vc, jwt_vc_json, sd-jwt VC. More than 150 countries are supported,
* an issuer of proof of identity. This issuer performs an identity document verification. The processing is done by our partner Docaposte and uses the ID360 platform. This issuer supports all verifiable credentials formats; ldp_vc, jwt_vc_json, sd-jwt VC. The sd-jwt format is compiant with the EUDI PID.

To add an issuer you just have to click on the visible button or on the contrary invisible to remove it from the wallet.

All those verifiable credentials are **signed by Talao** with its DIDs available [here](https://talao.co/sandbox/saas4ssi/dids).

## Add your external issuers

You can also add links to your own issuers in the wallet. For each issuer you will be asked to provide information regarding:

- the name of the issuer,
- the description of the issuer,
- the conditions for obtaining the verifiable credential,
- the user redirection link,
- the verifiable credential format,
- the category in which it is attached,
- the graphic elements for wallet rendering.

For an issuer to be added, it simply needs to be accessible in the smartphone's browser and implement the OIDC4VCI protocol used by the wallet.

Your issuers can be **private or public**. If they are private only your organization can add them in the configuration. If it is a public issuer, all organizations of the Wallet Provider Backend can add them in their wallets.

After issuer link setup to add your issuer you just have to clic on the visible button or on the contrary invisible to remove it from the wallet.

After updating the issuer marketplace do not forget to clic on the setup configuration button to save your configuration.

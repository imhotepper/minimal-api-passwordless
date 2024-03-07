# Minimal API PasswordLess

Passwordless authentication and authorization with .Net 8 Minimal Api + Microsoft IdentityModel JWT + In Memory EF database + SendGrid

## Boilerplate for passwordless authentication

The code in the repo contains all the endpoints needed to create passwordless authentication/authorization for any SPA.

The missing SendGrid key must be created at SendGrid side and added to the settings file in order to have the code working E2E

## How it is supposed to be used

1. Inside `appsettings.json` update the keys: `Issuer`, `Audience`,`Key`, `FROM_EMAIL` and `SENDGRID_API_KEY` with your own. SendGrid api key can be created on their site and used for free with some wide limits
2. Deploy the repo code to Azure or Heroku or any other hosting server
3. Open the `[YOUR_URL]/swagger` url
4. Use the endpoint `/api/{email}` with your email or a test email.
5. Check the inbox for the email specified above. The email sent from passwordless via sendgrid might arrive in your `SPAM` folder.
6. Click on the `Login` link in the email and copy the JWT token displayed in the page 
7. Use the api Swagger's `Authorize` button and add the token as: `Bearer [YOUR_TOKEN_HERE]`
8. Test the `/api/dashboard` from swagger and if the bearer is valid you should see the message returned `"[YOUR_EMAIL_HERE] is Authenticated! "`

**The api can be used, as a starting point, for any SPA that needs passwordless authentication on a backend written with .NET 8 Minimal API.**

<br>
<br>
Happy coding! <br>
@Imhotepp



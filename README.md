# SRP-6a Java Card Applet

This Java Card applet is an implementation of the Secure Remote Password (SRP-6a)
password-authenticated secure channel protocol. In combination with an
implementation of an off-card application, such as an Android application using
our [SRP-6A Android Library](https://github.com/mobilesec/secure-channel-srp6a-android-lib),
you can establish a secure communication channel that is mutually authenticated
with a PIN or password. This implementation relys on standard Java Card 2.2 API
functionality. Although secure elements with Java Card 2.2 API are usually
equipped with the necessary hardware for computation of modulo operations as used
in SRP, limitations of the standard Java Card 2.2 API prevent direct access to
the necessary cryptographic primitives. Hence, this makes it challenging to
implement SRP with acceptable performance. However, by exploiting the RSA
encryption API provided by the platform, we show that it is possible to compute
exponentiations and multiplications with support of the cryptographic
co-processor. This, and minor adaptations to the protocol, made it possible to
implement the SRP-6a server-side in a Java Card applet with reasonable
computation time. We presented this in our MoMM2014 paper (see LITERATURE section).



## DISCLAIMER

You are using this application at your own risk. *We are not responsible for any
damage caused by this application, incorrect usage or inaccuracies in this manual.*



## LITERATURE

- M. Hölzl, E. Asnake, R. Mayrhofer, and M. Roland: "*Mobile Application to Java Card Applet Communication using a Password-authenticated Secure Channel*," in Proceedings of the 12th International Conference on Advances in Mobile Computing & Multimedia (MoMM2014), pp. 147--156, ACM, December 2014.

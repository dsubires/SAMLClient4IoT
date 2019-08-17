# SAMLClient
Simple SAML client developed in JAVA. 
Clients developed in two ways: 
  - HTTP REDIRECT BIND
    [demo environment information]
     - device 1, which sends [20-60] authentication requests, is launched every 10 seconds. 10% of authentication requests will be failed attempts.
     - device 2, which sends [100-200] status updates to elasticsearch, is released every 15 seconds. 2% of device states will exceed the temperature threshold, which will trigger the notification mechanism to administrators.
     - the mesh device sends every 15 seconds [50-100] status updates through the restful web service of the devices.
  - POST BIND [outdated version]

Access an SP, after authentication on an IdP using a special authentication mechanism for devices (IoT). In particular, the deviceAuth module for the SimpleSAMLphp framework.
Module URL: https://github.com/dsubires/simplesamlphp-module-deviceauth


  

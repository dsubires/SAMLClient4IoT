# SAMLClient
Simple SAML client developed in JAVA. 
Clients developed in two ways: 
  - HTTP REDIRECT BIND
    [demo environment information]
      - el dispositivo 1, que envía [20-60] peticiones de autenticación, se lanza cada 10 segundos. El 10% de las peticiones de autenticación serán intentos fallidos.  
      - el dispositivo 2, que envía [100-200] actualizaciones de estado a elasticsearch. El 2% de los estados de dispositivos superarán el umbral de temperatua, lo que disparará el mecanismo de notificación a los administradores.
      - el dispositivo mesh envía [50-100] actualizaciones de estado a través del web service restful de los dispositivos.
  - POST BIND [outdated version]

Access an SP, after authentication on an IdP using a special authentication mechanism for devices (IoT). In particular, the deviceAuth module for the SimpleSAMLphp framework.
Module URL: https://github.com/dsubires/simplesamlphp-module-deviceauth


  

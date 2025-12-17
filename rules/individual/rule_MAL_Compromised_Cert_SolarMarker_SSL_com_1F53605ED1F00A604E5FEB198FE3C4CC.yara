import "pe"

rule MAL_Compromised_Cert_SolarMarker_SSL_com_1F53605ED1F00A604E5FEB198FE3C4CC {
   meta:
      description         = "Detects SolarMarker with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2023-09-08"
      version             = "1.0"

      hash                = "8f536b3f85b999cf0a899de83523c8fea56647e6be6880fbbc7856e1cb802902"
      malware             = "SolarMarker"
      malware_type        = "Remote access tool"
      malware_notes       = "A remote access tool active 2020-2023. Installs a VNC client to perform on-device-fraud."

      signer              = "AAA AUTO SERVICES LIMITED"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "1f:53:60:5e:d1:f0:0a:60:4e:5f:eb:19:8f:e3:c4:cc"
      cert_thumbprint     = "B63A2EEFF477EC805D9E784E63827BE5397212D5"
      cert_valid_from     = "2023-09-08"
      cert_valid_to       = "2024-09-07"

      country             = "GB"
      state               = "???"
      locality            = "Chorley"
      email               = "???"
      rdn_serial_number   = "07853928"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "1f:53:60:5e:d1:f0:0a:60:4e:5f:eb:19:8f:e3:c4:cc"
      )
}

import "pe"

rule MAL_Compromised_Cert_NetSupport_RAT_SSL_com_5258128CB8E2C4816C2F9F13BAF422D7 {
   meta:
      description         = "Detects NetSupport RAT with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2024-07-02"
      version             = "1.0"

      hash                = "a8b56d92607550947e223d22e0baba8a05c8a3f1c9efe6db30c2a54bc6dec3ff"
      malware             = "NetSupport RAT"
      malware_type        = "Remote access tool"
      malware_notes       = "This is a weaponised Remote Management and monitoring tool."

      signer              = "Mac Softwares Limited"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com Code Signing Intermediate CA RSA R1"
      cert_serial         = "52:58:12:8c:b8:e2:c4:81:6c:2f:9f:13:ba:f4:22:d7"
      cert_thumbprint     = "2DDDE1128529FA31F6B7E6D817DB09667BF3E803"
      cert_valid_from     = "2024-07-02"
      cert_valid_to       = "2025-07-02"

      country             = "GB"
      state               = "England"
      locality            = "Epsom"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com Code Signing Intermediate CA RSA R1" and
         sig.serial == "52:58:12:8c:b8:e2:c4:81:6c:2f:9f:13:ba:f4:22:d7"
      )
}

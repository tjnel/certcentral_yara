import "pe"

rule MAL_Compromised_Cert_SolarMarker_SSL_com_582754520B29E5E364C2EA504C4E33FF {
   meta:
      description         = "Detects SolarMarker with compromised cert (SSL.com)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2023-11-14"
      version             = "1.0"

      hash                = "a31d955304360eade30679137269659a9c7b1e53aecb2eb7e616a4ad0f91c655"
      malware             = "SolarMarker"
      malware_type        = "Remote access tool"
      malware_notes       = "A remote access tool active 2020-2023. Installs a VNC client to perform on-device-fraud."

      signer              = "ТОВ \"Гейм Трейд\""
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "58:27:54:52:0b:29:e5:e3:64:c2:ea:50:4c:4e:33:ff"
      cert_thumbprint     = "E9A61165463CEE5B9F502E78C52539CBF128DAE9"
      cert_valid_from     = "2023-11-14"
      cert_valid_to       = "2024-11-13"

      country             = "UA"
      state               = "Kiev"
      locality            = "Kyiv"
      email               = "???"
      rdn_serial_number   = "45350408"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "58:27:54:52:0b:29:e5:e3:64:c2:ea:50:4c:4e:33:ff"
      )
}

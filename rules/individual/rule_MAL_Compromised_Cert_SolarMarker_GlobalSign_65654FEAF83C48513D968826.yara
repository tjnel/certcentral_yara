import "pe"

rule MAL_Compromised_Cert_SolarMarker_GlobalSign_65654FEAF83C48513D968826 {
   meta:
      description         = "Detects SolarMarker with compromised cert (GlobalSign)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2020-08-04"
      version             = "1.0"

      hash                = "3e99b59df79d1ab9ff7386e209d9135192661042bcdf44dde85ff4687ff57d01"
      malware             = "SolarMarker"
      malware_type        = "Remote access tool"
      malware_notes       = "A remote access tool active 2020-2023. Installs a VNC client to perform on-device-fraud."

      signer              = "PRIVATE SECURITY ORGANIZATION BARK LLC"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign Extended Validation CodeSigning CA - SHA256 - G3"
      cert_serial         = "65:65:4f:ea:f8:3c:48:51:3d:96:88:26"
      cert_thumbprint     = "3CF8740A9D201C771CAE0D3E975725C8FC66160C"
      cert_valid_from     = "2020-08-04"
      cert_valid_to       = "2021-04-29"

      country             = "RU"
      state               = "Moscow"
      locality            = "Moscow"
      email               = "e.peskova@gepardt.ru"
      rdn_serial_number   = "1167746707138"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign Extended Validation CodeSigning CA - SHA256 - G3" and
         sig.serial == "65:65:4f:ea:f8:3c:48:51:3d:96:88:26"
      )
}

import "pe"

rule MAL_Compromised_Cert_BuerLoader_Sectigo_008FE807310D98357A59382090634B93F0 {
   meta:
      description         = "Detects BuerLoader with compromised cert (Sectigo)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2021-02-16"
      version             = "1.0"

      hash                = "045a7318a9e2e550208c0c7e9fc805068df19fa73823ac3acaa049a46c4045ee"
      malware             = "BuerLoader"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "MAVE MEDIA"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo RSA Code Signing CA"
      cert_serial         = "00:8f:e8:07:31:0d:98:35:7a:59:38:20:90:63:4b:93:f0"
      cert_thumbprint     = "ACD6CF38D03C355DDB84B96A7365BFC1738A0EC5"
      cert_valid_from     = "2021-02-16"
      cert_valid_to       = "2022-02-16"

      country             = "BE"
      state               = "Antwerpen"
      locality            = "Ranst"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo RSA Code Signing CA" and
         sig.serial == "00:8f:e8:07:31:0d:98:35:7a:59:38:20:90:63:4b:93:f0"
      )
}

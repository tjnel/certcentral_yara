import "pe"

rule MAL_Compromised_Cert_ZhongStealer_Sectigo_4C3EDBD0B6450CB8BF2B506032A5B7B2 {
   meta:
      description         = "Detects ZhongStealer with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-06-07"
      version             = "1.0"

      hash                = "1718b2f1372dbbe9df071205fe749bcefe8857af7e376c812168f2590e1dcb27"
      malware             = "ZhongStealer"
      malware_type        = "Infostealer"
      malware_notes       = "This malware often hosts secondary payloads on CDNs. This signer name is \"Kingston Technology Company, Inc\"; but was confirmed not to be a legitimate certificate used by Kingston."

      signer              = "Kingston Technology Company, Inc"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA E36"
      cert_serial         = "4c:3e:db:d0:b6:45:0c:b8:bf:2b:50:60:32:a5:b7:b2"
      cert_thumbprint     = "8A99A90A9B2095B52AD670B1BF5CAC68A9784FF8"
      cert_valid_from     = "2025-06-07"
      cert_valid_to       = "2026-05-25"

      country             = "US"
      state               = "California"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA E36" and
         sig.serial == "4c:3e:db:d0:b6:45:0c:b8:bf:2b:50:60:32:a5:b7:b2"
      )
}

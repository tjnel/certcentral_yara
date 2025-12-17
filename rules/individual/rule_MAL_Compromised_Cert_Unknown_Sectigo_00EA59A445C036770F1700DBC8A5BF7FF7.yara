import "pe"

rule MAL_Compromised_Cert_Unknown_Sectigo_00EA59A445C036770F1700DBC8A5BF7FF7 {
   meta:
      description         = "Detects Unknown with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2022-07-26"
      version             = "1.0"

      hash                = "31cccd7f8e7db26c12f522c0f1519ffa459fdd0120e4911c03fb2fcf2432ca00"
      malware             = "Unknown"
      malware_type        = "Adware"
      malware_notes       = "This app is PCAppStore. PCAppStore is known to be downloaded by accident by users and known to connect to a wide range of risky behaviors and network connections. While adware typically doesn't get its certificate revoked, the issuer decided to in this case. This software represents a latent risk and we recommend removing it."

      signer              = "Fast Corporate Ltd"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA R36"
      cert_serial         = "00:ea:59:a4:45:c0:36:77:0f:17:00:db:c8:a5:bf:7f:f7"
      cert_thumbprint     = "D1EA027182B1EB2D017AE359045C048CB9B60402"
      cert_valid_from     = "2022-07-26"
      cert_valid_to       = "2023-07-26"

      country             = "IL"
      state               = "Tel Aviv"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA R36" and
         sig.serial == "00:ea:59:a4:45:c0:36:77:0f:17:00:db:c8:a5:bf:7f:f7"
      )
}

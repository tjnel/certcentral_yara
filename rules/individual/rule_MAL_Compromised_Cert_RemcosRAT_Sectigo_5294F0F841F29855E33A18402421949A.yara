import "pe"

rule MAL_Compromised_Cert_RemcosRAT_Sectigo_5294F0F841F29855E33A18402421949A {
   meta:
      description         = "Detects RemcosRAT with compromised cert (Sectigo)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2022-11-07"
      version             = "1.0"

      hash                = "538b607c03aa2d0960c396529399921f957f421a3ca084d140316e2ee21889cc"
      malware             = "RemcosRAT"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Integrated Plotting Solutions Limited"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA R36"
      cert_serial         = "52:94:f0:f8:41:f2:98:55:e3:3a:18:40:24:21:94:9a"
      cert_thumbprint     = "7747F957A70822B5FBC2274495742FC33607B09F"
      cert_valid_from     = "2022-11-07"
      cert_valid_to       = "2023-11-07"

      country             = "GB"
      state               = "Sheffield"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA R36" and
         sig.serial == "52:94:f0:f8:41:f2:98:55:e3:3a:18:40:24:21:94:9a"
      )
}

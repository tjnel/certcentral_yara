import "pe"

rule MAL_Compromised_Cert_ScreenConnectLoader_Certum_6002EF4359609E6BE08215CC40F9B377 {
   meta:
      description         = "Detects ScreenConnectLoader with compromised cert (Certum)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-12-23"
      version             = "1.0"

      hash                = "8bba91fb8bc5629d55b2068e548843cea582365e712213533647e2e79525c4fa"
      malware             = "ScreenConnectLoader"
      malware_type        = "Remote access tool"
      malware_notes       = "Sent via email disguised as a social security document."

      signer              = "BEACH JOHN WILLIAM"
      cert_issuer_short   = "Certum"
      cert_issuer         = "Certum Code Signing 2021 CA"
      cert_serial         = "60:02:ef:43:59:60:9e:6b:e0:82:15:cc:40:f9:b3:77"
      cert_thumbprint     = "5EF6C0869F593CF53FF99B7497EE41DABB18755E"
      cert_valid_from     = "2025-12-23"
      cert_valid_to       = "2026-12-23"

      country             = "US"
      state               = "Minnesota"
      locality            = "Wabasha"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Certum Code Signing 2021 CA" and
         sig.serial == "60:02:ef:43:59:60:9e:6b:e0:82:15:cc:40:f9:b3:77"
      )
}
